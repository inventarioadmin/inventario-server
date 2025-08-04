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
// Rota de Login com logs detalhados
app.post('/api/login', async (req, res) => {
    try {
        const { username, password, type } = req.body;
        console.log('Login attempt - Body:', req.body); // Log completo do body

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

// Listar dispositivos
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