require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs').promises;

const app = express();

// Middlewares básicos
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Conexão MongoDB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('MongoDB conectado'))
    .catch(err => console.error('Erro MongoDB:', err));

// Models
const Company = require('./models/Company');
const Device = require('./models/Device');

// Schema do User
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['superadmin', 'admin'], required: true },
    isActive: { type: Boolean, default: true }
});

const User = mongoose.model('User', userSchema);

// NOVOS SCHEMAS PARA SINCRONIZAÇÃO
const syncSchema = new mongoose.Schema({
    companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true },
    androidId: { type: String, required: true },
    type: { type: String, enum: ['upload', 'download'], required: true },
    filename: { type: String, required: true },
    originalName: { type: String, required: true },
    fileSize: { type: Number, required: true },
    timestamp: { type: Date, default: Date.now },
    status: { type: String, enum: ['pending', 'completed', 'error'], default: 'completed' }
});

const SyncLog = mongoose.model('SyncLog', syncSchema);

const loadSchema = new mongoose.Schema({
    companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true },
    type: { type: String, enum: ['parcelas', 'parametros'], required: true },
    filename: { type: String, required: true },
    originalName: { type: String, required: true },
    description: { type: String },
    uploadedBy: { type: String },
    uploadDate: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true },
    version: { type: String, required: true },
    fileSize: { type: Number, default: 0 }
});

const Load = mongoose.model('Load', loadSchema);

// CONFIGURAÇÃO DO MULTER PARA UPLOAD DE ARQUIVOS
const storage = multer.diskStorage({
    destination: async (req, file, cb) => {
        const dir = path.join(__dirname, 'uploads', req.user.companyId.toString());
        try {
            await fs.mkdir(dir, { recursive: true });
            cb(null, dir);
        } catch (error) {
            cb(error);
        }
    },
    filename: (req, file, cb) => {
        const timestamp = new Date().toISOString().replace(/:/g, '-').split('.')[0];
        cb(null, `${timestamp}_${file.originalname}`);
    }
});

const upload = multer({ 
    storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'text/csv' || file.originalname.endsWith('.csv')) {
            cb(null, true);
        } else {
            cb(new Error('Apenas arquivos CSV são permitidos'));
        }
    }
});

// Middleware de Autenticação
const auth = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ message: 'Token não fornecido' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        if (decoded.role === 'superadmin') {
            const user = await User.findById(decoded.userId);
            if (!user || !user.isActive) {
                return res.status(401).json({ message: 'Usuário não autorizado' });
            }
            req.user = user;
        } else if (decoded.role === 'admin') {
            const company = await Company.findById(decoded.companyId);
            if (!company || !company.isActive) {
                return res.status(401).json({ message: 'Empresa não autorizada' });
            }
            req.company = company;
            req.user = { role: 'admin', companyId: company._id };
        }

        next();
    } catch (error) {
        console.error('Erro auth:', error);
        res.status(401).json({ message: 'Token inválido' });
    }
};

// MIDDLEWARE PARA AUTENTICAÇÃO MOBILE
const mobileAuth = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ success: false, message: 'Token não fornecido' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        if (decoded.type !== 'mobile') {
            return res.status(401).json({ success: false, message: 'Token inválido para mobile' });
        }

        const company = await Company.findById(decoded.companyId);
        if (!company || !company.isActive) {
            return res.status(401).json({ success: false, message: 'Empresa não autorizada' });
        }

        const device = await Device.findOne({
            androidId: decoded.androidId,
            companyId: decoded.companyId,
            isActive: true
        });

        if (!device) {
            return res.status(401).json({ success: false, message: 'Dispositivo não autorizado' });
        }

        req.company = company;
        req.device = device;
        req.user = { companyId: company._id, androidId: decoded.androidId };
        
        next();
    } catch (error) {
        console.error('Erro auth mobile:', error);
        res.status(401).json({ success: false, message: 'Token inválido' });
    }
};

// Middleware Superadmin
const superadminOnly = (req, res, next) => {
    if (req.user.role !== 'superadmin') {
        return res.status(403).json({ message: 'Acesso negado' });
    }
    next();
};

// Middleware para verificar licença
const checkLicense = async (req, res, next) => {
    try {
        if (!req.company) {
            return res.status(404).json({ message: 'Empresa não encontrada' });
        }

        if (!req.company.isActive) {
            return res.status(403).json({ message: 'Empresa inativa' });
        }

        if (new Date() > new Date(req.company.expirationDate)) {
            return res.status(403).json({ message: 'Licença expirada' });
        }

        next();
    } catch (error) {
        res.status(500).json({ message: 'Erro ao verificar licença' });
    }
};

// Rota de Login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password, type } = req.body;
        console.log('Login attempt - Body:', req.body);

        // Validação básica
        if (!username || !password || !type) {
            console.log('Missing fields:', { username: !username, password: !password, type: !type });
            return res.status(400).json({
                success: false,
                message: 'Todos os campos são obrigatórios'
            });
        }

        if (type === 'superadmin') {
            console.log('Attempting superadmin login for:', username);
            const user = await User.findOne({ username, role: 'superadmin' });
            console.log('Superadmin search result:', user ? 'Found' : 'Not found');

            if (user) {
                const isPasswordValid = await bcrypt.compare(password, user.password);
                console.log('Password check result:', isPasswordValid ? 'Valid' : 'Invalid');

                if (isPasswordValid && user.isActive) {
                    const token = jwt.sign(
                        { userId: user._id, role: 'superadmin' },
                        process.env.JWT_SECRET,
                        { expiresIn: '24h' }
                    );
                    console.log('Login successful, token generated');
                    return res.json({
                        success: true,
                        token,
                        role: 'superadmin'
                    });
                }
            }
        } 
        else if (type === 'admin') {
            console.log('Attempting company login for:', username);
            const company = await Company.findOne({ username });
            console.log('Company search result:', company ? 'Found' : 'Not found');

            if (company) {
                const isPasswordValid = await bcrypt.compare(password, company.password);
                console.log('Password check result:', isPasswordValid ? 'Valid' : 'Invalid');

                if (isPasswordValid && company.isActive) {
                    const token = jwt.sign(
                        { companyId: company._id, role: 'admin' },
                        process.env.JWT_SECRET,
                        { expiresIn: '24h' }
                    );
                    console.log('Login successful, token generated');
                    return res.json({
                        success: true,
                        token,
                        role: 'admin'
                    });
                }
            }
        }

        console.log('Login failed - Invalid credentials');
        return res.status(401).json({
            success: false,
            message: 'Credenciais inválidas'
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Erro interno do servidor'
        });
    }
});

// Rotas do Superadmin
app.get('/api/companies', auth, superadminOnly, async (req, res) => {
    try {
        const companies = await Company.find();
        
        const companiesWithDevices = await Promise.all(companies.map(async company => {
            const deviceCount = await Device.countDocuments({
                companyId: company._id,
                isActive: true
            });
            return {
                ...company.toObject(),
                deviceCount
            };
        }));
        
        res.json({ success: true, companies: companiesWithDevices });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erro ao listar empresas' });
    }
});

app.post('/api/companies', auth, superadminOnly, async (req, res) => {
    try {
        const { name, username, password, maxDevices, durationDays } = req.body;

        const existingCompany = await Company.findOne({ username });
        if (existingCompany) {
            return res.status(400).json({ success: false, message: 'Usuário já existe' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const expirationDate = new Date();
        expirationDate.setDate(expirationDate.getDate() + parseInt(durationDays));

        const company = new Company({
            name,
            username,
            password: hashedPassword,
            maxDevices: parseInt(maxDevices),
            expirationDate,
            isActive: true
        });

        await company.save();
        res.json({ success: true, company });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erro ao criar empresa' });
    }
});

app.put('/api/companies/:id', auth, superadminOnly, async (req, res) => {
    try {
        const updates = {};
        if (req.body.name) updates.name = req.body.name;
        if (req.body.maxDevices) updates.maxDevices = parseInt(req.body.maxDevices);

        const company = await Company.findByIdAndUpdate(
            req.params.id,
            { $set: updates },
            { new: true }
        );

        if (!company) {
            return res.status(404).json({ success: false, message: 'Empresa não encontrada' });
        }

        res.json({ success: true, company });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erro ao atualizar empresa' });
    }
});

app.put('/api/companies/:id/toggle', auth, superadminOnly, async (req, res) => {
    try {
        const company = await Company.findById(req.params.id);
        if (!company) {
            return res.status(404).json({ success: false, message: 'Empresa não encontrada' });
        }

        company.isActive = !company.isActive;
        await company.save();

        if (!company.isActive) {
            await Device.updateMany(
                { companyId: company._id },
                { $set: { isActive: false } }
            );
        }

        res.json({ success: true, company });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erro ao alterar status' });
    }
});

app.put('/api/companies/:id/renew', auth, superadminOnly, async (req, res) => {
    try {
        const { durationDays } = req.body;
        const company = await Company.findById(req.params.id);
        
        if (!company) {
            return res.status(404).json({ success: false, message: 'Empresa não encontrada' });
        }

        const newExpirationDate = new Date();
        newExpirationDate.setDate(newExpirationDate.getDate() + parseInt(durationDays));
        
        company.expirationDate = newExpirationDate;
        await company.save();

        res.json({ success: true, company });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erro ao renovar empresa' });
    }
});

app.delete('/api/companies/:id', auth, superadminOnly, async (req, res) => {
    try {
        const company = await Company.findById(req.params.id);
        if (!company) {
            return res.status(404).json({ success: false, message: 'Empresa não encontrada' });
        }

        await Device.deleteMany({ companyId: company._id });
        await company.deleteOne();

        res.json({ success: true, message: 'Empresa excluída com sucesso' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erro ao excluir empresa' });
    }
});

// Rotas da Empresa
app.get('/api/company/info', auth, checkLicense, async (req, res) => {
    try {
        const deviceCount = await Device.countDocuments({
            companyId: req.company._id,
            isActive: true
        });

        res.json({
            success: true,
            company: {
                name: req.company.name,
                maxDevices: req.company.maxDevices,
                deviceCount,
                expirationDate: req.company.expirationDate,
                isActive: req.company.isActive
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erro ao buscar informações' });
    }
});

// Listar dispositivos (ATUALIZADO COM INFO DE SYNC)
app.get('/api/devices/list', auth, checkLicense, async (req, res) => {
    try {
        const devices = await Device.find({ companyId: req.user.companyId });
        
        const devicesWithSync = await Promise.all(devices.map(async device => {
            const lastSync = await SyncLog.findOne({
                companyId: req.user.companyId,
                androidId: device.androidId
            }).sort({ timestamp: -1 });

            return {
                ...device.toObject(),
                lastSync: lastSync ? {
                    type: lastSync.type,
                    timestamp: lastSync.timestamp,
                    filename: lastSync.originalName
                } : null
            };
        }));

        res.json({
            success: true,
            devices: devicesWithSync
        });

    } catch (error) {
        console.error('Erro ao listar dispositivos:', error);
        res.status(500).json({ success: false, message: 'Erro ao listar dispositivos' });
    }
});

// Listar dispositivos (mantém compatibilidade com painel antigo)
app.get('/api/devices', auth, async (req, res) => {
    try {
        const devices = await Device.find({ companyId: req.user.companyId });
        res.json({ success: true, devices });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erro ao listar dispositivos' });
    }
});

// Deletar dispositivo
app.delete('/api/devices/:androidId', auth, async (req, res) => {
    try {
        const device = await Device.findOneAndDelete({
            androidId: req.params.androidId,
            companyId: req.user.companyId
        });

        if (!device) {
            return res.status(404).json({ success: false, message: 'Dispositivo não encontrado' });
        }

        res.json({ success: true, message: 'Dispositivo excluído com sucesso' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erro ao excluir dispositivo' });
    }
});

// Registrar dispositivo
app.post('/api/devices', auth, async (req, res) => {
    try {
        const { androidId, description } = req.body;

        const deviceCount = await Device.countDocuments({
            companyId: req.user.companyId,
            isActive: true
        });

        if (deviceCount >= req.company.maxDevices) {
            return res.status(400).json({ success: false, message: 'Limite de dispositivos atingido' });
        }

        const existingDevice = await Device.findOne({ 
            androidId,
            companyId: req.user.companyId
        });

        if (existingDevice) {
            return res.status(400).json({ success: false, message: 'Dispositivo já registrado' });
        }

        const device = new Device({
            androidId,
            description,
            companyId: req.user.companyId,
            isActive: true
        });

        await device.save();
        res.json({ success: true, device });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erro ao registrar dispositivo' });
    }
});

// Toggle dispositivo
app.put('/api/devices/:androidId/toggle', auth, async (req, res) => {
    try {
        const device = await Device.findOne({
            androidId: req.params.androidId,
            companyId: req.user.companyId
        });

        if (!device) {
            return res.status(404).json({ success: false, message: 'Dispositivo não encontrado' });
        }

        device.isActive = !device.isActive;
        await device.save();

        res.json({ success: true, device });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erro ao alterar status do dispositivo' });
    }
});

// Rota de verificação do aplicativo Android
app.post('/api/verify-device', auth, async (req, res) => {
    try {
        const { androidId } = req.body;
        
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Acesso negado' });
        }

        const device = await Device.findOne({
            androidId,
            companyId: req.user.companyId,
            isActive: true
        });

        if (!device) {
            return res.status(401).json({ success: false, message: 'Dispositivo não autorizado' });
        }

        device.lastAccess = new Date();
        await device.save();

        res.json({ success: true, message: 'Dispositivo verificado' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erro na verificação' });
    }
});

// Rota de login do aplicativo Android
app.post('/api/mobile/login', async (req, res) => {
    try {
        const { username, password, androidId } = req.body;

        const company = await Company.findOne({ username, isActive: true });
        if (!company) {
            return res.status(401).json({ success: false, message: 'Credenciais inválidas' });
        }

        const isValidPassword = await bcrypt.compare(password, company.password);
        if (!isValidPassword) {
            return res.status(401).json({ success: false, message: 'Credenciais inválidas' });
        }

        if (new Date() > new Date(company.expirationDate)) {
            return res.status(403).json({ success: false, message: 'Licença expirada' });
        }

        const device = await Device.findOne({
            androidId,
            companyId: company._id,
            isActive: true
        });

        if (!device) {
            return res.status(401).json({ success: false, message: 'Dispositivo não autorizado' });
        }

        device.lastLogin = new Date();
        await device.save();

        const token = jwt.sign(
            { companyId: company._id, androidId, type: 'mobile' },
            process.env.JWT_SECRET,
            { expiresIn: '30d' }
        );

        res.json({ success: true, token });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erro ao realizar login' });
    }
});

// ENDPOINTS DE SINCRONIZAÇÃO PARA APP (aceita token admin)

// 1. UPLOAD DE DADOS COLETADOS (aceita token admin) - CORRIGIDO
app.post('/api/app/sync/upload', auth, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, message: 'Arquivo não fornecido' });
        }

        // NOVO: Determinar tipo baseado no nome do arquivo
        let type = 'parametros'; // padrão
        let description = req.file.originalname;
        
        if (req.file.originalname.toLowerCase().includes('ua_') || 
            req.file.originalname.toLowerCase().includes('parcela')) {
            type = 'parcelas';
            description = `Parcelas - ${req.file.originalname}`;
        } else if (req.file.originalname.toLowerCase().includes('cub_') || 
                   req.file.originalname.toLowerCase().includes('cubagem')) {
            type = 'cubagem';
            description = `Cubagem - ${req.file.originalname}`;
        } else if (req.file.originalname.toLowerCase().includes('param')) {
            type = 'parametros';
            description = `Parâmetros - ${req.file.originalname}`;
        }

        // Para token admin, pega o androidId do body ou usa um padrão
        const androidId = req.body.androidId || 'admin-device';

        // NOVO: Mover arquivo para pasta loads e registrar como Load
        const loadDir = path.join(__dirname, 'loads', req.user.companyId.toString());
        await fs.mkdir(loadDir, { recursive: true });
        
        const newFilename = req.file.filename; // Mantém o nome com timestamp
        const newPath = path.join(loadDir, newFilename);
        
        // Move de uploads/ para loads/
        await fs.rename(req.file.path, newPath);

        // Registra como Load no banco para aparecer na lista
        const load = new Load({
            companyId: req.user.companyId,
            type,
            filename: newFilename,
            originalName: req.file.originalname,
            description,
            uploadedBy: 'Mobile App',
            version: new Date().toISOString().split('T')[0], // Data como versão
            fileSize: req.file.size
        });

        await load.save();

        // Registra o log de sync
        const syncLog = new SyncLog({
            companyId: req.user.companyId,
            androidId: androidId,
            type: 'upload',
            filename: newFilename,
            originalName: req.file.originalname,
            fileSize: req.file.size
        });

        await syncLog.save();

        res.json({
            success: true,
            message: 'Dados enviados com sucesso',
            uploadId: syncLog._id,
            loadId: load._id,
            timestamp: syncLog.timestamp
        });

    } catch (error) {
        console.error('Erro no upload:', error);
        res.status(500).json({ success: false, message: 'Erro no upload: ' + error.message });
    }
});

// 2. LISTAR CARGAS DISPONÍVEIS (aceita token admin)
app.get('/api/app/sync/loads', auth, checkLicense, async (req, res) => {
    try {
        const loads = await Load.find({
            companyId: req.user.companyId,
            isActive: true
        }).sort({ uploadDate: -1 });

        const formattedLoads = loads.map(load => ({
            id: load._id,
            type: load.type,
            description: load.description || load.originalName,
            version: load.version,
            uploadDate: load.uploadDate,
            size: load.fileSize || 0
        }));

        res.json({
            success: true,
            loads: formattedLoads
        });

    } catch (error) {
        console.error('Erro ao listar cargas:', error);
        res.status(500).json({ success: false, message: 'Erro ao listar cargas' });
    }
});

// 3. DOWNLOAD DE CARGA (aceita token admin)
app.get('/api/app/sync/download/:loadId', auth, checkLicense, async (req, res) => {
    try {
        const load = await Load.findOne({
            _id: req.params.loadId,
            companyId: req.user.companyId,
            isActive: true
        });

        if (!load) {
            return res.status(404).json({ success: false, message: 'Carga não encontrada' });
        }

        const filePath = path.join(__dirname, 'loads', req.user.companyId.toString(), load.filename);
        
        try {
            await fs.access(filePath);
        } catch {
            return res.status(404).json({ success: false, message: 'Arquivo não encontrado no servidor' });
        }

        // Para token admin, usa um androidId padrão
        const androidId = req.body.androidId || 'admin-device';

        const syncLog = new SyncLog({
            companyId: req.user.companyId,
            androidId: androidId,
            type: 'download',
            filename: load.filename,
            originalName: load.originalName,
            fileSize: load.fileSize || 0
        });

        await syncLog.save();

        res.setHeader('Content-Disposition', `attachment; filename="${load.originalName}"`);
        res.setHeader('Content-Type', 'text/csv');
        res.sendFile(filePath);

    } catch (error) {
        console.error('Erro no download:', error);
        res.status(500).json({ success: false, message: 'Erro no download: ' + error.message });
    }
});

// ===== ENDPOINTS ORIGINAIS DE SINCRONIZAÇÃO (para tokens mobile) =====

// 1. UPLOAD DE DADOS COLETADOS (do app para servidor)
app.post('/api/mobile/sync/upload', mobileAuth, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, message: 'Arquivo não fornecido' });
        }

        const syncLog = new SyncLog({
            companyId: req.user.companyId,
            androidId: req.user.androidId,
            type: 'upload',
            filename: req.file.filename,
            originalName: req.file.originalname,
            fileSize: req.file.size
        });

        await syncLog.save();

        req.device.lastAccess = new Date();
        await req.device.save();

        res.json({
            success: true,
            message: 'Dados enviados com sucesso',
            uploadId: syncLog._id,
            timestamp: syncLog.timestamp
        });

    } catch (error) {
        console.error('Erro no upload:', error);
        res.status(500).json({ success: false, message: 'Erro no upload: ' + error.message });
    }
});

// 2. LISTAR CARGAS DISPONÍVEIS (para o app)
app.get('/api/mobile/sync/loads', mobileAuth, async (req, res) => {
    try {
        const loads = await Load.find({
            companyId: req.user.companyId,
            isActive: true
        }).sort({ uploadDate: -1 });

        const formattedLoads = loads.map(load => ({
            id: load._id,
            type: load.type,
            description: load.description || load.originalName,
            version: load.version,
            uploadDate: load.uploadDate,
            size: load.fileSize || 0
        }));

        res.json({
            success: true,
            loads: formattedLoads
        });

    } catch (error) {
        console.error('Erro ao listar cargas:', error);
        res.status(500).json({ success: false, message: 'Erro ao listar cargas' });
    }
});

// 3. DOWNLOAD DE CARGA (do servidor para app)
app.get('/api/mobile/sync/download/:loadId', mobileAuth, async (req, res) => {
    try {
        const load = await Load.findOne({
            _id: req.params.loadId,
            companyId: req.user.companyId,
            isActive: true
        });

        if (!load) {
            return res.status(404).json({ success: false, message: 'Carga não encontrada' });
        }

        const filePath = path.join(__dirname, 'loads', req.user.companyId.toString(), load.filename);
        
        try {
            await fs.access(filePath);
        } catch {
            return res.status(404).json({ success: false, message: 'Arquivo não encontrado no servidor' });
        }

        const syncLog = new SyncLog({
            companyId: req.user.companyId,
            androidId: req.user.androidId,
            type: 'download',
            filename: load.filename,
            originalName: load.originalName,
            fileSize: load.fileSize || 0
        });

        await syncLog.save();

        req.device.lastAccess = new Date();
        await req.device.save();

        res.setHeader('Content-Disposition', `attachment; filename="${load.originalName}"`);
        res.setHeader('Content-Type', 'text/csv');
        res.sendFile(filePath);

    } catch (error) {
        console.error('Erro no download:', error);
        res.status(500).json({ success: false, message: 'Erro no download: ' + error.message });
    }
});

// 4. UPLOAD DE CARGAS (admin para servidor)
app.post('/api/admin/loads/upload', auth, checkLicense, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, message: 'Arquivo não fornecido' });
        }

        const { type, description, version } = req.body;

        if (!type || !['parcelas', 'parametros'].includes(type)) {
            return res.status(400).json({ success: false, message: 'Tipo inválido' });
        }

        if (!version) {
            return res.status(400).json({ success: false, message: 'Versão é obrigatória' });
        }

        const loadDir = path.join(__dirname, 'loads', req.user.companyId.toString());
        await fs.mkdir(loadDir, { recursive: true });
        
        const newFilename = `${type}_${version}_${Date.now()}.csv`;
        const newPath = path.join(loadDir, newFilename);
        
        await fs.rename(req.file.path, newPath);

        const load = new Load({
            companyId: req.user.companyId,
            type,
            filename: newFilename,
            originalName: req.file.originalname,
            description,
            uploadedBy: req.company.username,
            version,
            fileSize: req.file.size
        });

        await load.save();

        res.json({
            success: true,
            message: 'Carga enviada com sucesso',
            load: {
                id: load._id,
                type: load.type,
                description: load.description,
                version: load.version,
                uploadDate: load.uploadDate
            }
        });

    } catch (error) {
        console.error('Erro no upload da carga:', error);
        res.status(500).json({ success: false, message: 'Erro no upload: ' + error.message });
    }
});

// 5. LISTAR CARGAS (para admin)
app.get('/api/admin/loads', auth, checkLicense, async (req, res) => {
    try {
        const loads = await Load.find({
            companyId: req.user.companyId
        }).sort({ uploadDate: -1 });

        res.json({
            success: true,
            loads: loads.map(load => ({
                id: load._id,
                type: load.type,
                description: load.description,
                version: load.version,
                originalName: load.originalName,
                uploadDate: load.uploadDate,
                uploadedBy: load.uploadedBy,
                isActive: load.isActive,
                fileSize: load.fileSize
            }))
        });

    } catch (error) {
        console.error('Erro ao listar cargas:', error);
        res.status(500).json({ success: false, message: 'Erro ao listar cargas' });
    }
});

// 6. ATIVAR/DESATIVAR CARGA
app.put('/api/admin/loads/:loadId/toggle', auth, checkLicense, async (req, res) => {
    try {
        const load = await Load.findOne({
            _id: req.params.loadId,
            companyId: req.user.companyId
        });

        if (!load) {
            return res.status(404).json({ success: false, message: 'Carga não encontrada' });
        }

        load.isActive = !load.isActive;
        await load.save();

        res.json({
            success: true,
            message: `Carga ${load.isActive ? 'ativada' : 'desativada'} com sucesso`,
            load: {
                id: load._id,
                isActive: load.isActive
            }
        });

    } catch (error) {
        console.error('Erro ao alterar status da carga:', error);
        res.status(500).json({ success: false, message: 'Erro ao alterar status' });
    }
});

// 7. HISTÓRICO DE SINCRONIZAÇÕES
app.get('/api/admin/sync/history', auth, checkLicense, async (req, res) => {
    try {
        const history = await SyncLog.find({
            companyId: req.user.companyId
        }).sort({ timestamp: -1 }).limit(100);

        res.json({
            success: true,
            history: history.map(log => ({
                id: log._id,
                androidId: log.androidId,
                type: log.type,
                filename: log.originalName,
                fileSize: log.fileSize,
                timestamp: log.timestamp,
                status: log.status
            }))
        });

    } catch (error) {
        console.error('Erro ao buscar histórico:', error);
        res.status(500).json({ success: false, message: 'Erro ao buscar histórico' });
    }
});

// 8. BAIXAR DADOS COLETADOS (admin)
app.get('/api/admin/sync/download/:syncId', auth, checkLicense, async (req, res) => {
    try {
        const syncLog = await SyncLog.findOne({
            _id: req.params.syncId,
            companyId: req.user.companyId,
            type: 'upload'
        });

        if (!syncLog) {
            return res.status(404).json({ success: false, message: 'Arquivo não encontrado' });
        }

        const filePath = path.join(__dirname, 'uploads', req.user.companyId.toString(), syncLog.filename);
        
        try {
            await fs.access(filePath);
        } catch {
            return res.status(404).json({ success: false, message: 'Arquivo não encontrado no servidor' });
        }

        res.setHeader('Content-Disposition', `attachment; filename="${syncLog.originalName}"`);
        res.setHeader('Content-Type', 'text/csv');
        res.sendFile(filePath);

    } catch (error) {
        console.error('Erro no download:', error);
        res.status(500).json({ success: false, message: 'Erro no download: ' + error.message });
    }
});

// 9. EXCLUIR CARGA
app.delete('/api/admin/loads/:loadId', auth, checkLicense, async (req, res) => {
    try {
        const load = await Load.findOne({
            _id: req.params.loadId,
            companyId: req.user.companyId
        });

        if (!load) {
            return res.status(404).json({ success: false, message: 'Carga não encontrada' });
        }

        // Remove o arquivo físico
        const filePath = path.join(__dirname, 'loads', req.user.companyId.toString(), load.filename);
        try {
            await fs.unlink(filePath);
            console.log('Arquivo removido:', filePath);
        } catch (error) {
            console.log('Arquivo não encontrado para remoção:', filePath);
        }

        // Remove do banco de dados
        await load.deleteOne();

        res.json({
            success: true,
            message: 'Carga excluída com sucesso'
        });

    } catch (error) {
        console.error('Erro ao excluir carga:', error);
        res.status(500).json({ success: false, message: 'Erro ao excluir carga' });
    }
});

// DEBUG: Verificar arquivos na pasta loads
app.get('/api/debug/loads/:companyId', auth, async (req, res) => {
    try {
        const loadsDir = path.join(__dirname, 'loads', req.params.companyId);
        
        try {
            const files = await fs.readdir(loadsDir);
            res.json({
                success: true,
                directory: loadsDir,
                files: files,
                count: files.length
            });
        } catch (error) {
            res.json({
                success: false,
                directory: loadsDir,
                error: 'Pasta não existe',
                files: []
            });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Rotas estáticas
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/superadmin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'superadmin.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'company-panel.html'));
});

// Handler para rotas não encontradas
app.use((req, res) => {
    res.status(404).json({ success: false, message: 'Rota não encontrada' });
});

// Handler de erros global
app.use((error, req, res, next) => {
    console.error('Erro não tratado:', error);
    res.status(500).json({ 
        success: false, 
        message: 'Erro interno do servidor'
    });
});

// Inicia o servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});