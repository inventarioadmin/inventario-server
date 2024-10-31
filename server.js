// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Conectar ao MongoDB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('MongoDB Conectado'))
    .catch(err => console.error('Erro MongoDB:', err));

// Modelos
const User = mongoose.model('User', {
    username: String,
    password: String,
    isAdmin: Boolean
});

const Device = mongoose.model('Device', {
    imei: String,
    description: String,
    isActive: { type: Boolean, default: true },
    lastLogin: Date
});

// Middleware de autenticação
const authMiddleware = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ message: 'Token não fornecido' });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);
        
        if (!user) return res.status(401).json({ message: 'Usuário não encontrado' });
        
        req.user = user;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Token inválido' });
    }
};

// Rotas
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ success: false, message: 'Credenciais inválidas' });
        }

        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '30d' }
        );

        res.json({
            success: true,
            authKey: token,
            isAdmin: user.isAdmin
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Rota para dispositivos (protegida)
app.get('/api/devices', authMiddleware, async (req, res) => {
    try {
        if (!req.user.isAdmin) {
            return res.status(403).json({ message: 'Acesso negado' });
        }
        const devices = await Device.find();
        res.json(devices);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.post('/api/devices', authMiddleware, async (req, res) => {
    try {
        if (!req.user.isAdmin) {
            return res.status(403).json({ message: 'Acesso negado' });
        }
        const device = new Device(req.body);
        await device.save();
        res.json({ success: true, device });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Rota para a página admin
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});