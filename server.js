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
    status: { type: String, enum: ['pending', 'completed', 'error'], default: 'completed' },
    conteudo: { type: String, default: '' } // NOVO: texto do CSV exportado pelo coletor
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
    fileSize: { type: Number, default: 0 },
    conteudo: { type: String, default: '' } // NOVO: o texto do CSV guardado no banco
});

const Load = mongoose.model('Load', loadSchema);

// ===== FATIA 1 - Passo 2: schema da Ordem de Serviço (O.S.) =====
const osSchema = new mongoose.Schema({
    companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true },
    loadId: { type: mongoose.Schema.Types.ObjectId, ref: 'Load', required: true },
    nome: { type: String, required: true },        // nome da O.S. (começa igual ao nome da carga)
    criadaEm: { type: Date, default: Date.now },
    estado: { type: String, enum: ['ativa', 'desativada', 'concluida'], default: 'ativa' }, // NOVO
    totalParcelas: { type: Number, default: 0 },
    // A lista de parcelas da O.S. Nesta fatia só guardamos a chave e os campos de origem.
    // Os campos de status (coletor, dataHora, situação) entram na Fatia 2.
    parcelas: [{
        chave: { type: String, required: true },
        numero: String,
        projeto: String,
        fazenda: String,
        talhao: String,
        lat: Number,
        lng: Number,
        situacao: String,
        lider: String,
        dataHora: String,
        motivo: String
    }]
});

const OrdemServico = mongoose.model('OrdemServico', osSchema);

// ===== FATIA 1: leitura do CSV de parcelas =====

// Monta a chave única de uma parcela. ESTE formato tem que ser IGUAL no app depois:
// PROJETO|FAZENDA|TALHAO|NUMERO — sem espaço nas pontas, tudo MAIÚSCULO, espaços internos colapsados.
function montarChaveParcela(projeto, fazenda, talhao, numero) {
    const limpar = (s) => (s || '').toString().trim().toUpperCase().replace(/\s+/g, ' ');
    return [limpar(projeto), limpar(fazenda), limpar(talhao), limpar(numero)].join('|');
}

// Lê o texto do CSV de uma carga de parcelas e devolve a lista de parcelas com suas chaves.
function extrairParcelasDoCsv(conteudoCsv) {
    if (!conteudoCsv || !conteudoCsv.trim()) {
        return { ok: false, motivo: 'CSV vazio', parcelas: [] };
    }
    // Remove o BOM (arquivos do Excel costumam vir com ele) e aceita quebra de linha do Windows ou Linux.
    let texto = conteudoCsv.replace(/^\uFEFF/, '');
    const linhas = texto.split(/\r?\n/).filter(l => l.trim() !== '');
    if (linhas.length < 2) {
        return { ok: false, motivo: 'CSV sem linhas de dados', parcelas: [] };
    }
    // No cabeçalho, descobre em qual coluna está cada campo (tolera acento e maiúsc/minúsc).
    const semAcento = (s) => s.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    const cabecalho = linhas[0].split(';').map(h => semAcento(h.trim().toLowerCase()));
    const acharCol = (nome) => cabecalho.findIndex(h => h.includes(nome));
    const iNumero  = acharCol('numero_parcela');
    const iProjeto = acharCol('projeto');
    const iFazenda = acharCol('fazenda');
    const iTalhao  = acharCol('talhao');
    const iUtmX    = acharCol('utm_x');   // no seu CSV isto é a LONGITUDE (ex: -50,63)
    const iUtmY    = acharCol('utm_y');   // no seu CSV isto é a LATITUDE  (ex: -24,01)
    if (iNumero < 0 || iProjeto < 0 || iFazenda < 0 || iTalhao < 0) {
        return { ok: false, motivo: 'Cabeçalho não tem as colunas esperadas (numero_parcela, projeto, fazenda, talhao)', parcelas: [], cabecalho };
    }
    // Converte "-50,63" (vírgula) em número -50.63. Devolve null se não for número.
    const coordNum = (txt) => {
        if (!txt) return null;
        const n = parseFloat(txt.toString().trim().replace(',', '.'));
        return isNaN(n) ? null : n;
    };
    const vistas = new Set();
    const parcelas = [];
    for (let i = 1; i < linhas.length; i++) {
        const campos = linhas[i].split(';');
        const numero  = (campos[iNumero]  || '').trim();
        const projeto = (campos[iProjeto] || '').trim();
        const fazenda = (campos[iFazenda] || '').trim();
        const talhao  = (campos[iTalhao]  || '').trim();
        if (!numero && !projeto && !fazenda && !talhao) continue; // linha em branco
        const chave = montarChaveParcela(projeto, fazenda, talhao, numero);
        if (vistas.has(chave)) continue; // ignora chave repetida
        vistas.add(chave);
        const lng = iUtmX >= 0 ? coordNum(campos[iUtmX]) : null;
        const lat = iUtmY >= 0 ? coordNum(campos[iUtmY]) : null;
        parcelas.push({ chave, numero, projeto, fazenda, talhao, lat, lng });
    }
    return { ok: true, motivo: '', parcelas };
}

// CONFIGURAÇÃO DO MULTER — memória (o conteúdo vai para o MongoDB, não para o disco).
// Isso resolve o sumiço de arquivos quando o Render reinicia.
const storage = multer.memoryStorage();

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

// Nova rota para atualizar campo específico da empresa
app.put('/api/companies/:id/update-field', auth, superadminOnly, async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;
        
        // Valida se é apenas um campo por vez
        const fields = Object.keys(updates);
        if (fields.length !== 1) {
            return res.status(400).json({ 
                success: false, 
                message: 'Apenas um campo pode ser atualizado por vez' 
            });
        }

        const field = fields[0];
        const value = updates[field];

        // Validações específicas por campo
        if (field === 'username') {
            if (!value || value.trim() === '') {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Usuário não pode estar vazio' 
                });
            }
            
            // Verifica se username já existe em outra empresa
            const existingCompany = await Company.findOne({ 
                username: value.trim(),
                _id: { $ne: id }
            });
            
            if (existingCompany) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Este usuário já existe em outra empresa' 
                });
            }
        }

        if (field === 'name') {
            if (!value || value.trim() === '') {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Nome da empresa não pode estar vazio' 
                });
            }
        }

        if (field === 'maxDevices') {
            const num = parseInt(value);
            if (isNaN(num) || num < 1) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Limite de dispositivos deve ser um número maior que 0' 
                });
            }
        }

        if (field === 'expirationDate') {
            const date = new Date(value);
            if (isNaN(date.getTime())) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Data inválida' 
                });
            }
        }

        // Prepara a atualização
        const updateData = {};
        
        if (field === 'password') {
            // Hash da nova senha
            const salt = await bcrypt.genSalt(10);
            updateData.password = await bcrypt.hash(value, salt);
        } else if (field === 'maxDevices') {
            updateData.maxDevices = parseInt(value);
        } else if (field === 'expirationDate') {
            updateData.expirationDate = new Date(value);
        } else {
            updateData[field] = value.trim();
        }

        // Atualiza no banco
        const company = await Company.findByIdAndUpdate(
            id,
            { $set: updateData },
            { new: true }
        );

        if (!company) {
            return res.status(404).json({ 
                success: false, 
                message: 'Empresa não encontrada' 
            });
        }

        res.json({ 
            success: true, 
            message: `${getFieldDisplayName(field)} atualizado com sucesso`,
            company: company
        });

    } catch (error) {
        console.error('Erro ao atualizar campo:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Erro interno do servidor' 
        });
    }
});

// Função auxiliar para nomes dos campos
function getFieldDisplayName(field) {
    const names = {
        'name': 'Nome da empresa',
        'username': 'Usuário',
        'password': 'Senha',
        'maxDevices': 'Limite de dispositivos',
        'expirationDate': 'Data de expiração'
    };
    return names[field] || field;
}

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
            { expiresIn: '365d' }
        );

        res.json({ success: true, token });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erro ao realizar login' });
    }
});

// ENDPOINTS DE SINCRONIZAÇÃO PARA APP (aceita token admin)

// 1. UPLOAD (aceita token admin) — carga do admin OU exportação do coletor
app.post('/api/app/sync/upload', auth, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, message: 'Arquivo não fornecido' });
        }

        const conteudoCsv = req.file.buffer.toString('utf-8'); // o texto do CSV
        const isAdminUpload = req.body.type && req.body.version;

        if (isAdminUpload) {
            // Carga para dispositivos
            const { type, description, version } = req.body;
            const load = new Load({
                companyId: req.user.companyId,
                type,
                filename: `${type}_${version}_${Date.now()}.csv`,
                originalName: req.file.originalname,
                description,
                uploadedBy: 'Admin',
                version,
                fileSize: req.file.size,
                conteudo: conteudoCsv // guarda no banco
            });
            await load.save();
            res.json({ success: true, message: 'Carga enviada com sucesso', loadId: load._id });
        } else {
            // Exportação do coletor
            const androidId = req.body.androidId || 'admin-device';
            const syncLog = new SyncLog({
                companyId: req.user.companyId,
                androidId,
                type: 'upload',
                filename: `${Date.now()}_${req.file.originalname}`,
                originalName: req.file.originalname,
                fileSize: req.file.size,
                conteudo: conteudoCsv // guarda no banco
            });
            await syncLog.save();
            res.json({ success: true, message: 'Dados exportados enviados com sucesso', uploadId: syncLog._id });
        }
    } catch (error) {
        console.error('ERRO no upload:', error);
        res.status(500).json({ success: false, message: 'Erro no upload: ' + error.message });
    }
});

// NOVO: rota que o PORTAL usa para enviar carga (antes não existia -> dava 404)
app.post('/api/admin/loads/upload', auth, checkLicense, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, message: 'Arquivo não fornecido' });
        }
        const { type, description, version } = req.body;
        if (!type || !version) {
            return res.status(400).json({ success: false, message: 'Tipo e versão são obrigatórios' });
        }
        const load = new Load({
            companyId: req.user.companyId,
            type,
            filename: `${type}_${version}_${Date.now()}.csv`,
            originalName: req.file.originalname,
            description,
            uploadedBy: 'Admin',
            version,
            fileSize: req.file.size,
            conteudo: req.file.buffer.toString('utf-8')
        });
        await load.save();
        res.json({ success: true, message: 'Carga enviada com sucesso', loadId: load._id });
    } catch (error) {
        console.error('ERRO no upload do portal:', error);
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

        // NOVO: serve o conteúdo direto do MongoDB
        if (!load.conteudo) {
            return res.status(404).json({ success: false, message: 'Conteúdo da carga não encontrado' });
        }

        // Para token admin, usa um androidId padrão
        const androidId = req.query.androidId || req.headers['x-android-id'] || 'admin-device';

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
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.send(load.conteudo);

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
app.get('/api/mobile/sync/loads', mobileAuth, checkLicense, async (req, res) => {
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
app.get('/api/mobile/sync/download/:loadId', mobileAuth, checkLicense, async (req, res) => {
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

// ===== FATIA 1 - Passo 2: criar uma O.S. a partir de uma carga de parcelas =====
app.post('/api/admin/os/criar/:loadId', auth, checkLicense, async (req, res) => {
    try {
        const load = await Load.findOne({
            _id: req.params.loadId,
            companyId: req.user.companyId
        });
        if (!load) {
            return res.status(404).json({ success: false, message: 'Carga não encontrada' });
        }
        if (load.type !== 'parcelas') {
            return res.status(400).json({ success: false, message: 'Esta carga não é de parcelas (type = ' + load.type + ')' });
        }
        const resultado = extrairParcelasDoCsv(load.conteudo);
        if (!resultado.ok) {
            return res.status(400).json({ success: false, message: resultado.motivo, cabecalho: resultado.cabecalho });
        }
        // Trava anti-duplicata: se já existe O.S. desta carga, não cria outra.
        const jaExiste = await OrdemServico.findOne({
            companyId: req.user.companyId,
            loadId: load._id
        });
        if (jaExiste) {
            return res.status(409).json({
                success: false,
                message: 'Esta carga já tem uma O.S. criada',
                osId: jaExiste._id
            });
        }
        const os = new OrdemServico({
            companyId: req.user.companyId,
            loadId: load._id,
            nome: load.originalName,
            totalParcelas: resultado.parcelas.length,
            parcelas: resultado.parcelas
        });
        await os.save();
        res.json({
            success: true,
            message: 'O.S. criada com sucesso',
            osId: os._id,
            nome: os.nome,
            totalParcelas: os.totalParcelas
        });
    } catch (error) {
        console.error('Erro ao criar O.S.:', error);
        res.status(500).json({ success: false, message: 'Erro: ' + error.message });
    }
});

// ===== FATIA 2: dados de UMA O.S. para a tela (totais + resumo por líder/dia) =====
app.get('/api/admin/os/:osId', auth, checkLicense, async (req, res) => {
    try {
        const os = await OrdemServico.findOne({
            _id: req.params.osId,
            companyId: req.user.companyId
        });
        if (!os) {
            return res.status(404).json({ success: false, message: 'O.S. não encontrada' });
        }

        // Conta cada estado. Nesta fatia o app ainda não envia status,
        // então toda parcela sem 'situacao' definida conta como pendente.
        let feitas = 0, pendentes = 0, recusadas = 0, sincronizadas = 0;
        // Resumo por líder -> por dia. Ex: { "João": { "14/08/2026": 7 } }
        const porLider = {};

        for (const p of os.parcelas) {
            const situacao = p.situacao || 'pendente';
            if (situacao === 'feita') feitas++;
            else if (situacao === 'sincronizada') sincronizadas++;
            else if (situacao === 'recusada') recusadas++;
            else pendentes++;

            // Só entra no resumo quem tem líder registrado (feitas/sincronizadas)
            if ((situacao === 'feita' || situacao === 'sincronizada') && p.lider) {
                const lider = p.lider;
                const dia = p.dataHora || 'sem data';
                if (!porLider[lider]) porLider[lider] = {};
                porLider[lider][dia] = (porLider[lider][dia] || 0) + 1;
            }
        }

        // Transforma o resumo em lista pronta pra tela
        const resumoPorLider = Object.keys(porLider).sort().map(lider => ({
            lider,
            dias: Object.keys(porLider[lider]).sort().map(dia => ({
                dia,
                total: porLider[lider][dia]
            })),
            total: Object.values(porLider[lider]).reduce((a, b) => a + b, 0)
        }));

        // Lista enxuta de pontos para o mapa: chave, situação e coordenada.
        const pontos = os.parcelas
            .filter(p => typeof p.lat === 'number' && typeof p.lng === 'number')
            .map(p => ({
                chave: p.chave,
                numero: p.numero,
                situacao: p.situacao || 'pendente',
                lider: p.lider || null,
                lat: p.lat,
                lng: p.lng
            }));

        res.json({
            success: true,
            os: {
                id: os._id,
                nome: os.nome,
                criadaEm: os.criadaEm,
                totais: {
                    total: os.totalParcelas,
                    feitas,
                    sincronizadas,
                    pendentes,
                    recusadas
                },
                resumoPorLider,
                pontos
            }
        });
    } catch (error) {
        console.error('Erro ao buscar O.S.:', error);
        res.status(500).json({ success: false, message: 'Erro: ' + error.message });
    }
});


// ===== FATIA 3: devolver o mapa de status consolidado de uma carga =====
// O app manda o loadId (via URL) e recebe todas as parcelas já feitas/recusadas,
// de todas as equipes, pra pintar o mapa dele (verde/azul/amarelo).
app.get('/api/app/os/status/:loadId', auth, checkLicense, async (req, res) => {
    try {
        const os = await OrdemServico.findOne({
            companyId: req.user.companyId,
            loadId: req.params.loadId
        });
        // Se ainda não há O.S. dessa carga, não há status — devolve lista vazia (não é erro).
        if (!os) {
            return res.json({ success: true, existeOS: false, statuses: [] });
        }
        // Só devolve as parcelas que já têm situação (feita/recusada). As pendentes ficam de fora.
        const statuses = os.parcelas
            .filter(p => p.situacao === 'feita' || p.situacao === 'recusada')
            .map(p => ({
                chave: p.chave,
                situacao: p.situacao,
                lider: p.lider || null,
                dataHora: p.dataHora || null,
                motivo: p.motivo || ''
            }));
        res.json({
            success: true,
            existeOS: true,
            osId: os._id,
            total: statuses.length,
            statuses
        });
    } catch (error) {
        console.error('Erro ao devolver status:', error);
        res.status(500).json({ success: false, message: 'Erro: ' + error.message });
    }
});

// ===== FATIA 3: receber o mapa de status das equipes =====
// O app manda { loadId, statuses: [{ chave, situacao, lider, dataHora, motivo }] }.
// O servidor acha a O.S. daquela carga (cria se não existir) e pinta as parcelas.
app.post('/api/app/os/status', auth, checkLicense, async (req, res) => {
    try {
        const { loadId, statuses } = req.body;
        if (!loadId || !Array.isArray(statuses)) {
            return res.status(400).json({ success: false, message: 'loadId e statuses são obrigatórios' });
        }

        // Acha a O.S. daquela carga.
        let os = await OrdemServico.findOne({
            companyId: req.user.companyId,
            loadId: loadId
        });

        // Se não existir, cria automaticamente a partir da carga.
        if (!os) {
            const load = await Load.findOne({
                _id: loadId,
                companyId: req.user.companyId
            });
            if (!load) {
                return res.status(404).json({ success: false, message: 'Carga não encontrada para este loadId' });
            }
            if (load.type !== 'parcelas') {
                return res.status(400).json({ success: false, message: 'A carga não é de parcelas' });
            }
            const resultado = extrairParcelasDoCsv(load.conteudo);
            if (!resultado.ok) {
                return res.status(400).json({ success: false, message: 'Não foi possível ler a carga: ' + resultado.motivo });
            }
            os = new OrdemServico({
                companyId: req.user.companyId,
                loadId: load._id,
                nome: load.originalName,
                totalParcelas: resultado.parcelas.length,
                parcelas: resultado.parcelas
            });
            await os.save();
        }

        // Índice das parcelas da O.S. por chave, pra casar rápido.
        const porChave = {};
        os.parcelas.forEach((p, i) => { porChave[p.chave] = i; });

        let pintadas = 0, ignoradas = 0;
        for (const st of statuses) {
            const idx = porChave[st.chave];
            if (idx === undefined) { ignoradas++; continue; } // chave não existe nesta O.S.
            const p = os.parcelas[idx];
            // situação válida: feita ou recusada (o app manda uma dessas)
            p.situacao = (st.situacao === 'recusada') ? 'recusada' : 'feita';
            p.lider = st.lider || null;
            p.dataHora = st.dataHora || null;
            p.motivo = (st.situacao === 'recusada') ? (st.motivo || '') : '';
            pintadas++;
        }

        os.markModified('parcelas'); // avisa o Mongo que o array mudou
        await os.save();

        res.json({
            success: true,
            osId: os._id,
            nome: os.nome,
            pintadas,
            ignoradas
        });
    } catch (error) {
        console.error('Erro ao receber status:', error);
        res.status(500).json({ success: false, message: 'Erro: ' + error.message });
    }
});

// ===== BLOCO B: baixar planilha (CSV) dos status de uma O.S. =====
app.get('/api/admin/os/:osId/planilha', auth, checkLicense, async (req, res) => {
    try {
        const os = await OrdemServico.findOne({
            _id: req.params.osId,
            companyId: req.user.companyId
        });
        if (!os) {
            return res.status(404).json({ success: false, message: 'O.S. não encontrada' });
        }
        // Escapa ; e aspas pra não quebrar o CSV
        const esc = (v) => {
            const s = (v === undefined || v === null) ? '' : String(v);
            return s.includes(';') || s.includes('"') ? '"' + s.replace(/"/g, '""') + '"' : s;
        };
        const traduzSituacao = (s) => {
            if (s === 'feita') return 'Feita';
            if (s === 'recusada') return 'Recusada';
            return 'Pendente';
        };
        let csv = 'Numero Parcela;Projeto;Fazenda;Talhao;Situacao;Lider;Data;Motivo Recusa\n';
        for (const p of os.parcelas) {
            csv += [
                esc(p.numero),
                esc(p.projeto),
                esc(p.fazenda),
                esc(p.talhao),
                esc(traduzSituacao(p.situacao)),
                esc(p.lider || ''),
                esc(p.dataHora || ''),
                esc(p.motivo || '')
            ].join(';') + '\n';
        }
        // nome do arquivo: usa o nome da O.S., limpo
        const nomeLimpo = (os.nome || 'os').replace(/[^a-zA-Z0-9]+/g, '_').replace(/_+$/,'');
        res.setHeader('Content-Disposition', 'attachment; filename="status_' + nomeLimpo + '.csv"');
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.send('\uFEFF' + csv); // BOM pra o Excel abrir com acento certo
    } catch (error) {
        console.error('Erro ao gerar planilha da O.S.:', error);
        res.status(500).json({ success: false, message: 'Erro: ' + error.message });
    }
});

// ===== BLOCO B: mudar o estado de uma O.S. (ativa / desativada / concluida) =====
app.put('/api/admin/os/:osId/estado', auth, checkLicense, async (req, res) => {
    try {
        const { estado } = req.body;
        if (!['ativa', 'desativada', 'concluida'].includes(estado)) {
            return res.status(400).json({ success: false, message: 'Estado inválido' });
        }
        const os = await OrdemServico.findOne({
            _id: req.params.osId,
            companyId: req.user.companyId
        });
        if (!os) {
            return res.status(404).json({ success: false, message: 'O.S. não encontrada' });
        }
        os.estado = estado;
        await os.save();
        res.json({ success: true, osId: os._id, estado: os.estado });
    } catch (error) {
        console.error('Erro ao mudar estado da O.S.:', error);
        res.status(500).json({ success: false, message: 'Erro: ' + error.message });
    }
});

// ===== FATIA 2: excluir uma O.S. =====
app.delete('/api/admin/os/:osId', auth, checkLicense, async (req, res) => {
    try {
        const os = await OrdemServico.findOne({
            _id: req.params.osId,
            companyId: req.user.companyId
        });
        if (!os) {
            return res.status(404).json({ success: false, message: 'O.S. não encontrada' });
        }
        await os.deleteOne();
        res.json({ success: true, message: 'O.S. excluída com sucesso' });
    } catch (error) {
        console.error('Erro ao excluir O.S.:', error);
        res.status(500).json({ success: false, message: 'Erro: ' + error.message });
    }
});

// ===== FATIA 1 - Passo 2 (+ Bloco B): listar O.S., com estado e filtro opcional =====
app.get('/api/admin/os', auth, checkLicense, async (req, res) => {
    try {
        // filtro opcional por estado: /api/admin/os?estado=ativa (ou desativada, concluida)
        const filtro = { companyId: req.user.companyId };
        if (req.query.estado && ['ativa', 'desativada', 'concluida'].includes(req.query.estado)) {
            filtro.estado = req.query.estado;
        }
        const lista = await OrdemServico.find(filtro).sort({ criadaEm: -1 });
        res.json({
            success: true,
            total: lista.length,
            ordens: lista.map(os => ({
                id: os._id,
                nome: os.nome,
                criadaEm: os.criadaEm,
                estado: os.estado || 'ativa', // O.S. antigas sem estado contam como ativa
                totalParcelas: os.totalParcelas
            }))
        });
    } catch (error) {
        console.error('Erro ao listar O.S.:', error);
        res.status(500).json({ success: false, message: 'Erro: ' + error.message });
    }
});

// ===== FATIA 1 (teste): pré-visualizar as chaves de uma carga. NÃO grava nada. =====
app.get('/api/admin/os/preview/:loadId', auth, checkLicense, async (req, res) => {
    try {
        const load = await Load.findOne({
            _id: req.params.loadId,
            companyId: req.user.companyId
        });
        if (!load) {
            return res.status(404).json({ success: false, message: 'Carga não encontrada' });
        }
        if (load.type !== 'parcelas') {
            return res.status(400).json({ success: false, message: 'Esta carga não é de parcelas (type = ' + load.type + ')' });
        }
        const resultado = extrairParcelasDoCsv(load.conteudo);
        if (!resultado.ok) {
            return res.status(400).json({ success: false, message: resultado.motivo, cabecalho: resultado.cabecalho });
        }
        res.json({
            success: true,
            carga: load.originalName,
            total: resultado.parcelas.length,
            amostra: resultado.parcelas.slice(0, 10)
        });
    } catch (error) {
        console.error('Erro no preview da O.S.:', error);
        res.status(500).json({ success: false, message: 'Erro: ' + error.message });
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

        // NOVO: acompanha a O.S. — carga desativada => O.S. desativada; carga reativada => O.S. volta a ativa
        await OrdemServico.updateMany(
            { companyId: req.user.companyId, loadId: load._id },
            { $set: { estado: load.isActive ? 'ativa' : 'desativada' } }
        );

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

        // NOVO: a O.S. dessa carga vai para "desativada" (não some — preserva o histórico)
        await OrdemServico.updateMany(
            { companyId: req.user.companyId, loadId: load._id },
            { $set: { estado: 'desativada' } }
        );

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

// NOVA ROTA: Download de exportações do coletor
app.get('/api/admin/sync/download/:syncId', auth, checkLicense, async (req, res) => {
    try {
        const syncLog = await SyncLog.findOne({
            _id: req.params.syncId,
            companyId: req.user.companyId,
            type: 'upload'
        });

        if (!syncLog) {
            return res.status(404).json({ success: false, message: 'Exportação não encontrada' });
        }

        if (!syncLog.conteudo) {
            return res.status(404).json({ success: false, message: 'Conteúdo da exportação não encontrado' });
        }

        res.setHeader('Content-Disposition', `attachment; filename="${syncLog.originalName}"`);
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.send(syncLog.conteudo);

    } catch (error) {
        console.error('Erro no download da exportação:', error);
        res.status(500).json({ success: false, message: 'Erro no download: ' + error.message });
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

// DEBUG: Verificar onde está o arquivo da exportação
app.get('/api/debug/find-file/:syncId', auth, async (req, res) => {
    try {
        const syncLog = await SyncLog.findOne({
            _id: req.params.syncId,
            companyId: req.user.companyId
        });

        if (!syncLog) {
            return res.json({ error: 'SyncLog não encontrado' });
        }

        const companyDir = req.user.companyId.toString();
        
        // Verifica uploads/
        const uploadsPath = path.join(__dirname, 'uploads', companyDir, syncLog.filename);
        let uploadsExists = false;
        try {
            await fs.access(uploadsPath);
            uploadsExists = true;
        } catch (e) {}

        // Verifica loads/
        const loadsPath = path.join(__dirname, 'loads', companyDir, syncLog.filename);
        let loadsExists = false;
        try {
            await fs.access(loadsPath);
            loadsExists = true;
        } catch (e) {}

        res.json({
            syncLog: {
                id: syncLog._id,
                filename: syncLog.filename,
                originalName: syncLog.originalName,
                timestamp: syncLog.timestamp
            },
            paths: {
                uploads: {
                    path: uploadsPath,
                    exists: uploadsExists
                },
                loads: {
                    path: loadsPath,
                    exists: loadsExists
                }
            }
        });

    } catch (error) {
        res.json({ error: error.message });
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