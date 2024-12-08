require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');

const app = express();

// Middlewares básicos
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Conexão MongoDB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('MongoDB conectado'))
    .catch(err => console.error('Erro MongoDB:', err));

// Models (usando os existentes)
const Company = require('./models/Company');
const Device = require('./models/Device');

// Schema do User (apenas para autenticação)
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['superadmin', 'admin'], required: true },
    companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company' },
    isActive: { type: Boolean, default: true }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Middleware de Autenticação
const auth = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ message: 'Token não fornecido' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Se for token de empresa
        if (decoded.companyId) {
            const company = await Company.findById(decoded.companyId);
            if (!company || !company.isActive) {
                return res.status(401).json({ message: 'Empresa não autorizada' });
            }
            req.company = company; // Salva a empresa no request
            req.user = { role: 'admin', companyId: company._id }; // Adiciona informações do usuário
        } 
        // Se for token de usuário
        else if (decoded.userId) {
            const user = await User.findById(decoded.userId);
            if (!user || !user.isActive) {
                return res.status(401).json({ message: 'Usuário não autorizado' });
            }
            req.user = user;
            
            // Se for admin, carrega também a empresa
            if (user.role === 'admin' && user.companyId) {
                const company = await Company.findById(user.companyId);
                if (!company || !company.isActive) {
                    return res.status(401).json({ message: 'Empresa não autorizada' });
                }
                req.company = company;
            }
        }
        
        if (!req.user) {
            return res.status(401).json({ message: 'Token inválido' });
        }

        next();
    } catch (error) {
        console.error('Erro de autenticação:', error);
        res.status(401).json({ message: 'Token inválido' });
    }
};

// Middleware para verificar licença da empresa
const checkCompanyLicense = async (req, res, next) => {
    try {
        // Se não tem empresa no request, tenta buscar
        if (!req.company && req.user.companyId) {
            req.company = await Company.findById(req.user.companyId);
        }

        if (!req.company) {
            return res.status(404).json({
                success: false,
                message: 'Empresa não encontrada'
            });
        }

        // Verifica se a empresa está ativa
        if (!req.company.isActive) {
            return res.status(403).json({
                success: false,
                message: 'Empresa inativa'
            });
        }

        // Verifica se a licença expirou
        if (new Date() > new Date(req.company.expirationDate)) {
            return res.status(403).json({
                success: false,
                message: 'Licença expirada'
            });
        }

        next();
    } catch (error) {
        console.error('Erro ao verificar licença:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao verificar licença'
        });
    }
};

// Middleware Superadmin
const superadminOnly = (req, res, next) => {
    if (req.user.role !== 'superadmin') {
        return res.status(403).json({ message: 'Acesso negado' });
    }
    next();
};

// Rota de Login

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Primeiro tenta encontrar uma empresa
        const company = await Company.findOne({ username });
        
        if (company) {
            const isValidPassword = await bcrypt.compare(password, company.password);
            
            if (isValidPassword && company.isActive) {
                const token = jwt.sign(
                    { 
                        companyId: company._id,
                        role: 'admin'
                    },
                    process.env.JWT_SECRET,
                    { expiresIn: '24h' }
                );

                return res.json({
                    success: true,
                    token,
                    role: 'admin'
                });
            }
        }

        // Se não encontrou empresa, tenta encontrar usuário
        const user = await User.findOne({ username });
        
        if (user) {
            const isValidPassword = await bcrypt.compare(password, user.password);
            
            if (isValidPassword && user.isActive) {
                const token = jwt.sign(
                    { 
                        userId: user._id,
                        role: user.role,
                        companyId: user.companyId
                    },
                    process.env.JWT_SECRET,
                    { expiresIn: '24h' }
                );

                return res.json({
                    success: true,
                    token,
                    role: user.role
                });
            }
        }

        // Se chegou aqui, as credenciais são inválidas
        res.status(401).json({
            success: false,
            message: 'Credenciais inválidas'
        });

    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({
            success: false,
            message: 'Erro interno do servidor'
        });
    }
});

// Rota para verificar dispositivo Android
app.post('/api/verify-device', auth, async (req, res) => {
    try {
        const { androidId } = req.body;
        
        // Apenas admin pode verificar dispositivos
        if (req.user.role !== 'admin') {
            return res.status(403).json({ 
                success: false, 
                message: 'Acesso negado' 
            });
        }

        // Busca dispositivo
        const device = await Device.findOne({ 
            androidId,
            companyId: req.user.companyId
        });

        if (!device || !device.isActive) {
            return res.status(401).json({
                success: false,
                message: 'Dispositivo não autorizado'
            });
        }

        // Atualiza último acesso
        device.lastAccess = new Date();
        await device.save();

        res.json({
            success: true,
            message: 'Dispositivo verificado com sucesso'
        });

    } catch (error) {
        console.error('Erro na verificação:', error);
        res.status(500).json({
            success: false,
            message: 'Erro interno do servidor'
        });
    }
});

// Rotas para Superadmin
app.get('/api/companies', auth, superadminOnly, async (req, res) => {
    try {
        const companies = await Company.find().lean();
        console.log('Dados do banco:', companies); // Log 1
        
        const companiesWithDevices = await Promise.all(companies.map(async company => {
            const deviceCount = await Device.countDocuments({
                companyId: company._id,
                isActive: true
            });
            return {
                ...company,
                deviceCount
            };
        }));
        
        console.log('Dados enviados:', companiesWithDevices); // Log 2
        
        res.json({ 
            success: true, 
            companies: companiesWithDevices 
        });
    } catch (error) {
        console.error('Erro ao listar empresas:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Erro ao carregar lista de empresas' 
        });
    }
});

// Criar empresa (com validações)
app.post('/api/companies', auth, superadminOnly, async (req, res) => {
    try {
        const { name, username, password, maxDevices, durationDays } = req.body;

        // Validações
        if (!name || !username || !password || !maxDevices || !durationDays) {
            return res.status(400).json({
                success: false,
                message: 'Todos os campos são obrigatórios'
            });
        }

        // Verifica se username já existe
        const existingCompany = await Company.findOne({ username });
        if (existingCompany) {
            return res.status(400).json({
                success: false,
                message: 'Este nome de usuário já está em uso'
            });
        }

        // Cria hash da senha
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Calcula data de expiração
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

        res.json({
            success: true,
            company: {
                _id: company._id,
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
            message: 'Erro ao criar empresa'
        });
    }
});

// Atualizar empresa
app.put('/api/companies/:id', auth, superadminOnly, async (req, res) => {
    try {
        const { name, maxDevices } = req.body;
        const companyId = req.params.id;

        // Validações
        if (!name && !maxDevices) {
            return res.status(400).json({
                success: false,
                message: 'Nenhum dado para atualizar'
            });
        }

        const updateData = {};
        if (name) updateData.name = name;
        if (maxDevices) updateData.maxDevices = parseInt(maxDevices);

        const company = await Company.findByIdAndUpdate(
            companyId,
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
            company: {
                _id: company._id,
                name: company.name,
                username: company.username,
                maxDevices: company.maxDevices,
                expirationDate: company.expirationDate,
                isActive: company.isActive
            }
        });

    } catch (error) {
        console.error('Erro ao atualizar empresa:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao atualizar empresa'
        });
    }
});

// Ativar/Desativar empresa
app.put('/api/companies/:id/toggle', auth, superadminOnly, async (req, res) => {
    try {
        const company = await Company.findById(req.params.id);
        
        if (!company) {
            return res.status(404).json({
                success: false,
                message: 'Empresa não encontrada'
            });
        }

        company.isActive = !company.isActive;
        await company.save();

        // Se desativou a empresa, desativa todos os dispositivos
        if (!company.isActive) {
            await Device.updateMany(
                { companyId: company._id },
                { $set: { isActive: false } }
            );
        }

        res.json({
            success: true,
            company: {
                _id: company._id,
                name: company.name,
                username: company.username,
                maxDevices: company.maxDevices,
                expirationDate: company.expirationDate,
                isActive: company.isActive
            }
        });

    } catch (error) {
        console.error('Erro ao alterar status da empresa:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao alterar status da empresa'
        });
    }
});

// Renovar empresa
app.put('/api/companies/:id/renew', auth, superadminOnly, async (req, res) => {
    try {
        const { durationDays } = req.body;
        
        if (!durationDays || durationDays < 1) {
            return res.status(400).json({
                success: false,
                message: 'Duração inválida'
            });
        }

        const company = await Company.findById(req.params.id);
        
        if (!company) {
            return res.status(404).json({
                success: false,
                message: 'Empresa não encontrada'
            });
        }

        // Calcula nova data de expiração
        const newExpirationDate = new Date();
        newExpirationDate.setDate(newExpirationDate.getDate() + parseInt(durationDays));
        
        company.expirationDate = newExpirationDate;
        await company.save();

        res.json({
            success: true,
            company: {
                _id: company._id,
                name: company.name,
                username: company.username,
                maxDevices: company.maxDevices,
                expirationDate: company.expirationDate,
                isActive: company.isActive
            }
        });

    } catch (error) {
        console.error('Erro ao renovar empresa:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao renovar empresa'
        });
    }
});

// Excluir empresa
app.delete('/api/companies/:id', auth, superadminOnly, async (req, res) => {
    try {
        const company = await Company.findById(req.params.id);
        
        if (!company) {
            return res.status(404).json({
                success: false,
                message: 'Empresa não encontrada'
            });
        }

        // Primeiro remove todos os dispositivos da empresa
        await Device.deleteMany({ companyId: company._id });
        
        // Depois remove a empresa
        await company.remove();

        res.json({
            success: true,
            message: 'Empresa e seus dispositivos foram excluídos com sucesso'
        });

    } catch (error) {
        console.error('Erro ao excluir empresa:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao excluir empresa'
        });
    }
});


// Rota para informações da empresa
app.get('/api/company/info', auth, checkCompanyLicense, async (req, res) => {
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
                currentDevices: deviceCount,
                expirationDate: req.company.expirationDate,
                isActive: req.company.isActive
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Erro ao buscar informações da empresa'
        });
    }
});

// Rota para listar dispositivos
app.get('/api/devices/list', auth, checkCompanyLicense, async (req, res) => {
    try {
        const devices = await Device.find({ companyId: req.company._id });
        res.json({
            success: true,
            devices: devices
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Erro ao listar dispositivos'
        });
    }
});

// Rota para registrar dispositivo
app.post('/api/devices/register', auth, checkCompanyLicense, async (req, res) => {
    try {
        console.log('Corpo da requisição:', req.body);
        console.log('Empresa:', req.company);

        const { androidId, description } = req.body;

        // Validações básicas
        if (!androidId || !description) {
            return res.status(400).json({
                success: false,
                message: 'ID Android e descrição são obrigatórios'
            });
        }

        // Verifica se androidId já existe para esta empresa
        const existingDevice = await Device.findOne({
            androidId: androidId
        });

        if (existingDevice) {
            return res.status(400).json({
                success: false,
                message: 'Dispositivo já registrado'
            });
        }

        // Verifica limite de dispositivos
        const deviceCount = await Device.countDocuments({
            companyId: req.company._id,
            isActive: true
        });

        if (deviceCount >= req.company.maxDevices) {
            return res.status(400).json({
                success: false,
                message: 'Limite de dispositivos atingido'
            });
        }

        // Cria novo dispositivo
        const device = new Device({
            androidId,
            description,
            companyId: req.company._id,
            isActive: true
        });

        await device.save();

        res.json({
            success: true,
            device: device
        });
    } catch (error) {
        console.error('Erro ao registrar dispositivo:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao registrar dispositivo: ' + error.message
        });
    }
});

// Rota para ativar/desativar dispositivo
app.put('/api/devices/:androidId/toggle', auth, checkCompanyLicense, async (req, res) => {
    try {
        const device = await Device.findOne({
            companyId: req.company._id,
            androidId: req.params.androidId
        });

        if (!device) {
            return res.status(404).json({
                success: false,
                message: 'Dispositivo não encontrado'
            });
        }

        device.isActive = !device.isActive;
        await device.save();

        res.json({
            success: true,
            device: device
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Erro ao alterar status do dispositivo'
        });
    }
});

// Rota para login do app Android
app.post('/api/mobile/login', async (req, res) => {
    try {
        const { username, password, androidId } = req.body;

        // Busca empresa pelo username
        const company = await Company.findOne({ username });
        if (!company || !company.isActive) {
            return res.status(401).json({
                success: false,
                message: 'Credenciais inválidas'
            });
        }

        // Verifica senha
        const isValidPassword = await bcrypt.compare(password, company.password);
        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                message: 'Credenciais inválidas'
            });
        }

        // Verifica se licença está válida
        if (new Date() > new Date(company.expirationDate)) {
            return res.status(403).json({
                success: false,
                message: 'Licença expirada'
            });
        }

        // Busca dispositivo
        const device = await Device.findOne({
            companyId: company._id,
            androidId: androidId,
            isActive: true
        });

        if (!device) {
            return res.status(401).json({
                success: false,
                message: 'Dispositivo não autorizado'
            });
        }

        // Atualiza último login
        device.lastLogin = new Date();
        await device.save();

        // Gera token para o app
        const token = jwt.sign(
            {
                companyId: company._id,
                androidId: androidId,
                type: 'mobile'
            },
            process.env.JWT_SECRET,
            { expiresIn: '30d' }
        );

        res.json({
            success: true,
            token: token
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Erro ao realizar login'
        });
    }
});

// Rotas de páginas
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/superadmin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'superadmin.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'company-panel.html'));
});

// Inicia o servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});