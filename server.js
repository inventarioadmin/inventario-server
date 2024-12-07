require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();

// Configurações de segurança básicas
app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10kb' })); // Limita o tamanho das requisições
app.use(express.static(path.join(__dirname, 'public'))); // Serve arquivos estáticos de forma segura

// Conexão MongoDB com retry
const connectDB = async (retries = 5) => {
    while (retries) {
        try {
            const mongoURI = process.env.MONGODB_URI;
            if (!mongoURI) {
                throw new Error('MONGODB_URI não configurada');
            }

            await mongoose.connect(mongoURI, {
                useNewUrlParser: true,
                useUnifiedTopology: true,
                serverSelectionTimeoutMS: 5000,
                socketTimeoutMS: 45000,
            });

            console.log('MongoDB Conectado com sucesso');
            break;
        } catch (err) {
            retries -= 1;
            console.error(`Erro na conexão MongoDB. Tentativas restantes: ${retries}`);
            if (!retries) {
                console.error('Falha na conexão com MongoDB:', err);
                process.exit(1);
            }
            // Espera 5 segundos antes de tentar novamente
            await new Promise(resolve => setTimeout(resolve, 5000));
        }
    }
};

connectDB();

// Schemas com validação
const companySchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    username: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true },
    maxDevices: { type: Number, required: true, min: 1 },
    expirationDate: { type: Date, required: true },
    isActive: { type: Boolean, default: true }
}, { 
    collection: 'companies',
    timestamps: true 
});

const deviceSchema = new mongoose.Schema({
    androidId: { type: String, required: true },
    description: { type: String, required: true, trim: true },
    companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true },
    isActive: { type: Boolean, default: true },
    lastLogin: { type: Date, default: Date.now }
}, { 
    collection: 'devices',
    timestamps: true 
});

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true },
    role: { type: String, required: true, enum: ['superadmin', 'company', 'admin'] },
    isActive: { type: Boolean, default: true },
    companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company' }
}, { 
    collection: 'users',
    timestamps: true 
});

const Company = mongoose.model('Company', companySchema);
const Device = mongoose.model('Device', deviceSchema);
const User = mongoose.model('User', userSchema);

// Middleware de autenticação melhorado
const authMiddleware = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ success: false, message: 'Token não fornecido' });
        }

        let decoded;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET);
        } catch (err) {
            return res.status(401).json({ success: false, message: 'Token inválido ou expirado' });
        }

        if (decoded.role === 'superadmin') {
            req.user = { role: 'superadmin' };
            return next();
        }

        if (decoded.role === 'company') {
            const company = await Company.findById(decoded.companyId);
            if (!company || !company.isActive) {
                return res.status(401).json({ success: false, message: 'Empresa não autorizada' });
            }

            // Verifica se a licença está expirada
            if (company.expirationDate < new Date()) {
                return res.status(401).json({ success: false, message: 'Licença expirada' });
            }

            req.user = { role: 'company', companyId: company._id };
            return next();
        }

        const user = await User.findById(decoded.userId);
        if (!user || !user.isActive) {
            return res.status(401).json({ success: false, message: 'Usuário não autorizado' });
        }

        req.user = user;
        next();
    } catch (error) {
        console.error('Erro no middleware de autenticação:', error);
        res.status(401).json({ success: false, message: 'Erro de autenticação' });
    }
};

// Rate limiting simples
const rateLimit = {};
const rateLimitMiddleware = (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    
    if (rateLimit[ip]) {
        const timePassed = now - rateLimit[ip].timestamp;
        if (timePassed < 1000) { // 1 segundo
            rateLimit[ip].count++;
            if (rateLimit[ip].count > 10) { // Máximo 10 requisições por segundo
                return res.status(429).json({ 
                    success: false, 
                    message: 'Muitas requisições, tente novamente em alguns segundos' 
                });
            }
        } else {
            rateLimit[ip].timestamp = now;
            rateLimit[ip].count = 1;
        }
    } else {
        rateLimit[ip] = {
            timestamp: now,
            count: 1
        };
    }
    next();
};

// Aplicar rate limiting em todas as rotas
app.use(rateLimitMiddleware);

// Rota de login com validação melhorada
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username e senha são obrigatórios'
            });
        }

        const user = await User.findOne({ username }).select('+password');
        if (!user || !user.isActive) {
            return res.status(401).json({
                success: false,
                message: 'Credenciais inválidas'
            });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({
                success: false,
                message: 'Credenciais inválidas'
            });
        }

        let token;
        const tokenData = {
            userId: user._id.toString(),
            role: user.role
        };

        if (user.role === 'company') {
            const company = await Company.findById(user.companyId);
            if (!company || !company.isActive) {
                return res.status(401).json({
                    success: false,
                    message: 'Empresa não autorizada'
                });
            }
            tokenData.companyId = company._id.toString();
        }

        token = jwt.sign(tokenData, process.env.JWT_SECRET, { expiresIn: '24h' });

        res.json({
            success: true,
            authKey: token,
            role: user.role
        });

    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({
            success: false,
            message: 'Erro interno do servidor'
        });
    }
});

// Rotas estáticas com path absoluto
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/superadmin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'superadmin.html'));
});

// [Suas outras rotas existentes permanecem as mesmas...]

// Middleware de erro global melhorado
app.use((err, req, res, next) => {
    console.error('Erro não tratado:', err);
    
    if (err instanceof mongoose.Error) {
        return res.status(400).json({
            success: false,
            message: 'Erro de banco de dados',
            error: err.message
        });
    }

    res.status(500).json({
        success: false,
        message: 'Erro interno do servidor',
        error: process.env.NODE_ENV === 'production' ? 'Erro interno' : err.message
    });
});

// Fallback para rotas não encontradas
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Rota não encontrada'
    });
});

// Inicialização do servidor com tratamento de erro
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});

// Tratamento de erros não capturados
process.on('unhandledRejection', (err) => {
    console.error('Erro não tratado:', err);
    server.close(() => {
        process.exit(1);
    });
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('Recebido SIGTERM. Encerrando graciosamente...');
    server.close(() => {
        mongoose.connection.close(false, () => {
            console.log('Conexões fechadas. Processo encerrado.');
            process.exit(0);
        });
    });
});