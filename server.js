require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();

// Middlewares básicos
app.use(cors());
app.use(express.json());
app.use(express.static('public'));



// Conexão MongoDB
const mongoURI = process.env.MONGODB_URI.includes('/?') 
    ? process.env.MONGODB_URI.replace('/?', '/inventario?')
    : process.env.MONGODB_URI;

mongoose.connect(mongoURI)
    .then(() => console.log('MongoDB Conectado'))
    .catch(err => console.error('Erro MongoDB:', err));

// Limpa modelos anteriores
mongoose.models = {};

// Modelos
const Company = require('./models/Company');
const Device = require('./models/Device');

const User = mongoose.model('User', new mongoose.Schema({
    username: String,
    password: String,
    role: String,
    isActive: Boolean,
    companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company' }
}, { collection: 'users' }));

// Middleware de autenticação
const authMiddleware = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ message: 'Token não fornecido' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        if (decoded.role === 'superadmin') {
            req.user = { role: 'superadmin' };
            return next();
        }

        if (decoded.role === 'company') {
            const company = await Company.findById(decoded.companyId);
            if (!company || !company.isActive) {
                return res.status(401).json({ message: 'Empresa não autorizada' });
            }

            req.user = { role: 'company', companyId: company._id };
            return next();
        }

        const user = await User.findById(decoded.userId);
        if (!user) {
            return res.status(401).json({ message: 'Usuário não autorizado' });
        }

        req.user = user;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Token inválido' });
    }
};

// Rota de login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log('\n=== Tentativa de Login ===');
        console.log('Username recebido:', username);
        
        // Busca o usuário direto na coleção
        const user = await mongoose.connection.db.collection('users').findOne({ username });
        console.log('Usuário encontrado:', user ? 'Sim' : 'Não');
        
        if (!user) {
            console.log('Erro: Usuário não encontrado');
            return res.status(401).json({
                success: false,
                message: 'Credenciais inválidas'
            });
        }

        console.log('Role do usuário:', user.role);
        const passwordMatch = await bcrypt.compare(password, user.password);
        console.log('Senha correta:', passwordMatch ? 'Sim' : 'Não');

        if (!passwordMatch) {
            console.log('Erro: Senha incorreta');
            return res.status(401).json({
                success: false,
                message: 'Credenciais inválidas'
            });
        }

        let token;

        // Login de super admin
        if (user.role === 'superadmin') {
            console.log('Gerando token para super admin...');
            token = jwt.sign(
                { userId: user._id.toString(), role: 'superadmin' },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );

            return res.json({
                success: true,
                authKey: token,
                role: 'superadmin'
            });
        }

        // Login de empresa
        if (user.role === 'company') {
            const company = await Company.findById(user.companyId);
            if (!company || !company.isActive) {
                return res.status(401).json({
                    success: false,
                    message: 'Empresa não autorizada'
                });
            }

            token = jwt.sign(
                { userId: user._id.toString(), role: 'company', companyId: company._id.toString() },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );

            return res.json({
                success: true,
                authKey: token,
                role: 'company'
            });
        }

        // Login de admin (sistema atual)
        token = jwt.sign(
            { userId: user._id.toString(), role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        return res.json({
            success: true,
            authKey: token,
            role: user.role
        });

    } catch (error) {
        console.error('Erro no login:', error);
        return res.status(500).json({
            success: false,
            message: 'Erro interno do servidor'
        });
    }
});

// Rotas para super admin
// Criar empresa
app.post('/api/companies', authMiddleware, async (req, res) => {
    if (req.user.role !== 'superadmin') {
        return res.status(403).json({ success: false, message: 'Acesso não autorizado' });
    }

    try {
        const { name, username, password, maxDevices, durationDays } = req.body;
        
        // Validação dos campos
        if (!name || !username || !password || !maxDevices || !durationDays) {
            return res.status(400).json({ 
                success: false, 
                message: 'Todos os campos são obrigatórios' 
            });
        }

        // Verifica se já existe uma empresa com este usuário
        const existingCompany = await Company.findOne({ username });
        if (existingCompany) {
            return res.status(400).json({ 
                success: false, 
                message: 'Já existe uma empresa com este usuário' 
            });
        }
        
        const expirationDate = new Date();
        expirationDate.setDate(expirationDate.getDate() + parseInt(durationDays));
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Cria a empresa
        const company = new Company({
            name,
            username,
            password: hashedPassword,
            maxDevices,
            expirationDate,
            isActive: true
        });
        
        await company.save();
        
        res.json({ 
            success: true, 
            message: 'Empresa criada com sucesso',
            company: {
                name: company.name,
                username: company.username,
                maxDevices: company.maxDevices,
                expirationDate: company.expirationDate,
                isActive: company.isActive
            }
        });
    } catch (error) {
        console.error('Erro ao criar empresa:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Erro ao criar empresa: ' + error.message 
        });
    }
});

// Listar empresas
app.get('/api/companies', async (req, res) => {
    try {
        console.log('Buscando empresas...');
        const companies = await Company.find()
            .select('name username maxDevices expirationDate isActive')
            .lean();  // Usando lean() para melhor performance
            
        console.log('Empresas encontradas:', companies);
        res.json(companies);
    } catch (error) {
        console.error('Erro detalhado:', error);
        res.status(500).json({ 
            message: 'Erro ao buscar empresas',
            error: error.message 
        });
    }
});

// Rota para ativar/desativar empresa
app.put('/api/companies/:id/toggle', async (req, res) => {
    try {
        const company = await Company.findById(req.params.id);
        if (!company) {
            return res.status(404).json({ message: 'Empresa não encontrada' });
        }

        company.isActive = !company.isActive;
        await company.save();
        
        // Retorna lista atualizada
        const companies = await Company.find().sort('-createdAt');
        res.json(companies);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Rota para renovar empresa
app.put('/api/companies/:id/renew', async (req, res) => {
    try {
        const { durationDays } = req.body;
        const company = await Company.findById(req.params.id);
        
        if (!company) {
            return res.status(404).json({ message: 'Empresa não encontrada' });
        }

        const newExpirationDate = new Date();
        newExpirationDate.setDate(newExpirationDate.getDate() + parseInt(durationDays));
        
        company.expirationDate = newExpirationDate;
        company.isActive = true;
        await company.save();

        // Retorna lista atualizada
        const companies = await Company.find().sort('-createdAt');
        res.json(companies);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Rota para excluir empresa
app.delete('/api/companies/:id', async (req, res) => {
    try {
        await Company.findByIdAndDelete(req.params.id);
        
        // Retorna lista atualizada
        const companies = await Company.find().sort('-createdAt');
        res.json(companies);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.post('/api/company/login', async (req, res) => {
    try {
        const { username, password, deviceId } = req.body;
        console.log('\n=== Tentativa de Login de Empresa ===');
        console.log('Username recebido:', username);
        console.log('DeviceId recebido:', deviceId);
        
        const company = await Company.findOne({ username });
        console.log('Empresa encontrada:', company ? 'Sim' : 'Não');
        
        if (!company) {
            console.log('Erro: Empresa não encontrada');
            return res.status(401).json({
                success: false,
                message: 'Credenciais inválidas'
            });
        }

        // Verificar senha
        const passwordMatch = await bcrypt.compare(password, company.password);
        console.log('Senha correta:', passwordMatch ? 'Sim' : 'Não');

        if (!passwordMatch) {
            console.log('Erro: Senha incorreta');
            return res.status(401).json({
                success: false,
                message: 'Credenciais inválidas'
            });
        }

        if (!company.isActive) {
            return res.status(401).json({
                success: false,
                message: 'Empresa desativada'
            });
        }

        // Verificar validade da licença
        const hoje = new Date();
        const diasRestantes = Math.ceil((company.expirationDate - hoje) / (1000 * 60 * 60 * 24));

        // Gerar token
        const token = jwt.sign(
            { 
                companyId: company._id.toString(),
                role: 'company'
            },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        console.log('Token gerado com sucesso');
        
        return res.json({
            success: true,
            token: token,
            role: 'company',
            diasRestantes: diasRestantes,
            expired: diasRestantes <= 0
        });

    } catch (error) {
        console.error('Erro no login da empresa:', error);
        return res.status(500).json({
            success: false,
            message: 'Erro interno do servidor'
        });
    }
});

// Rota protegida para obter informações da empresa
app.get('/api/company/info', authMiddleware, async (req, res) => {
    if (req.user.role !== 'company') {
        return res.status(403).json({
            success: false,
            message: 'Acesso não autorizado'
        });
    }

    try {
        const company = await Company.findById(req.user.companyId)
            .select('name username maxDevices expirationDate isActive');
        
        if (!company) {
            return res.status(404).json({
                success: false,
                message: 'Empresa não encontrada'
            });
        }

        // Adicionar contagem de dispositivos
        const deviceCount = await Device.countDocuments({ companyId: req.user.companyId });
        const companyObj = company.toObject();
        companyObj.currentDevices = deviceCount;

        res.json({
            success: true,
            company: companyObj
        });
    } catch (error) {
        console.error('Erro ao buscar informações da empresa:', error);
        res.status(500).json({
            success: false,
            message: 'Erro interno do servidor'
        });
    }
});

app.post('/api/devices/register', authMiddleware, async (req, res) => {
    if (req.user.role !== 'company') {
        return res.status(403).json({
            success: false,
            message: 'Acesso não autorizado'
        });
    }

    try {
        const { androidId, description } = req.body;
        
        // Verificar dados obrigatórios
        if (!androidId || !description) {
            return res.status(400).json({
                success: false,
                message: 'ID Android e descrição são obrigatórios'
            });
        }

        // Verificar se a empresa ainda pode registrar dispositivos
        const company = await Company.findById(req.user.companyId);
        const deviceCount = await Device.countDocuments({ companyId: req.user.companyId });

        if (deviceCount >= company.maxDevices) {
            return res.status(400).json({
                success: false,
                message: 'Limite de dispositivos atingido'
            });
        }

        // Verificar se o dispositivo já existe para esta empresa
        const existingDevice = await Device.findOne({ 
            androidId: androidId,
            companyId: req.user.companyId
        });

        if (existingDevice) {
            return res.status(400).json({
                success: false,
                message: 'Dispositivo já registrado para esta empresa'
            });
        }

        // Criar novo dispositivo
        const device = new Device({
            androidId: androidId,
            description: description,
            companyId: req.user.companyId,
            isActive: true,
            lastLogin: new Date()
        });

        await device.save();

        // Retornar lista atualizada
        const devices = await Device.find({ companyId: req.user.companyId })
            .select('androidId description isActive lastLogin')
            .sort('-lastLogin');

        return res.json({
            success: true,
            message: 'Dispositivo registrado com sucesso',
            devices: devices
        });

    } catch (error) {
        console.error('Erro ao registrar dispositivo:', error);
        return res.status(500).json({
            success: false,
            message: 'Erro ao registrar dispositivo'
        });
    }
});

// Rota para listar dispositivos
app.get('/api/devices/list', authMiddleware, async (req, res) => {
    if (req.user.role !== 'company') {
        return res.status(403).json({
            success: false,
            message: 'Acesso não autorizado'
        });
    }

    try {
        const devices = await Device.find({ companyId: req.user.companyId })
            .select('androidId description isActive lastLogin')
            .sort('-lastLogin');

        res.json({
            success: true,
            devices: devices
        });

    } catch (error) {
        console.error('Erro ao listar dispositivos:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao listar dispositivos'
        });
    }
});

// Rota para ativar/desativar dispositivo
app.put('/api/devices/:androidId/toggle', authMiddleware, async (req, res) => {
    if (req.user.role !== 'company') {
        return res.status(403).json({
            success: false,
            message: 'Acesso não autorizado'
        });
    }

    try {
        const device = await Device.findOne({
            androidId: req.params.androidId,
            companyId: req.user.companyId
        });

        if (!device) {
            return res.status(404).json({
                success: false,
                message: 'Dispositivo não encontrado'
            });
        }

        device.isActive = !device.isActive;
        await device.save();

        const devices = await Device.find({ companyId: req.user.companyId })
            .select('androidId description isActive lastLogin')
            .sort('-lastLogin');

        res.json({
            success: true,
            devices: devices
        });

    } catch (error) {
        console.error('Erro ao alterar status do dispositivo:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao alterar status do dispositivo'
        });
    }
});

// Rota para deletar dispositivo
app.delete('/api/devices/:androidId', authMiddleware, async (req, res) => {
    if (req.user.role !== 'company') {
        return res.status(403).json({
            success: false,
            message: 'Acesso não autorizado'
        });
    }

    try {
        await Device.findOneAndDelete({
            androidId: req.params.androidId,
            companyId: req.user.companyId
        });

        const devices = await Device.find({ companyId: req.user.companyId })
            .select('androidId description isActive lastLogin')
            .sort('-lastLogin');

        res.json({
            success: true,
            devices: devices
        });

    } catch (error) {
        console.error('Erro ao excluir dispositivo:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao excluir dispositivo'
        });
    }
});



// Rotas para as interfaces web
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/superadmin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'superadmin.html'));
});

app.use((err, req, res, next) => {
    console.error('Erro não tratado:', err);
    res.status(500).json({
        success: false,
        message: 'Erro interno do servidor'
    });
});

// Inicialização do servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});