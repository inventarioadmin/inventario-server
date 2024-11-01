// server.js
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
    imei: { type: String, required: true, unique: true },
    description: String,
    isActive: { type: Boolean, default: true },
    lastLogin: Date,
    expirationDate: Date,
    createdAt: { type: Date, default: Date.now }
});

// Middleware de autenticação
const authMiddleware = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ message: 'Token não fornecido' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Se for admin, permite acesso direto
        if (decoded.isAdmin) {
            req.user = { isAdmin: true };
            return next();
        }

        // Se não for admin, verifica o usuário e o dispositivo
        const user = await User.findById(decoded.userId);
        const device = await Device.findOne({ imei: decoded.deviceId });
        
        if (!user || !device?.isActive) {
            return res.status(401).json({ message: 'Acesso não autorizado' });
        }
        
        req.user = user;
        req.device = device;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Token inválido' });
    }
};

// Rotas
app.post('/api/login', async (req, res) => {
    try {
        const { username, password, deviceId } = req.body;
        const user = await User.findOne({ username });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({
                success: false,
                message: 'Credenciais inválidas'
            });
        }

        // Se for acesso do painel admin, não verifica deviceId
        if (deviceId === 'admin-panel') {
            const token = jwt.sign(
                { userId: user._id, isAdmin: true },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );

            return res.json({
                success: true,
                authKey: token,
                isAdmin: true
            });
        }

        // Se não for admin, verifica o dispositivo
        const device = await Device.findOne({ imei: deviceId });
        if (!device || !device.isActive) {
            return res.status(401).json({
                success: false,
                message: 'Dispositivo não autorizado'
            });
        }

        // Verifica se o dispositivo está expirado
        if (device.expirationDate && new Date() > new Date(device.expirationDate)) {
            return res.status(401).json({
                success: false,
                message: 'Licença expirada'
            });
        }

        device.lastLogin = new Date();
        await device.save();

        const token = jwt.sign(
            { userId: user._id, deviceId },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            authKey: token
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Erro interno do servidor'
        });
    }
});

// Rota para listar dispositivos
app.get('/api/devices', authMiddleware, async (req, res) => {
    try {
        const devices = await Device.find().sort('-createdAt');
        res.json(devices);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Rota para adicionar dispositivo
app.post('/api/devices', authMiddleware, async (req, res) => {
    try {
        const { imei, description, durationDays = 30 } = req.body;

        // Calcula a data de expiração
        const expirationDate = new Date();
        expirationDate.setDate(expirationDate.getDate() + parseInt(durationDays));

        const device = new Device({
            imei,
            description,
            isActive: true,
            expirationDate
        });

        await device.save();
        res.json({ success: true, device });
    } catch (error) {
        if (error.code === 11000) {
            res.status(400).json({
                success: false,
                message: 'IMEI já cadastrado'
            });
        } else {
            res.status(500).json({
                success: false,
                message: error.message || 'Erro ao adicionar dispositivo'
            });
        }
    }
});

// Rota para excluir dispositivo
app.delete('/api/devices/:imei', authMiddleware, async (req, res) => {
    try {
        const device = await Device.findOneAndDelete({ imei: req.params.imei });
        
        if (!device) {
            return res.status(404).json({ 
                success: false, 
                message: 'Dispositivo não encontrado' 
            });
        }

        res.json({ 
            success: true, 
            message: 'Dispositivo removido com sucesso' 
        });
    } catch (error) {
        res.status(500).json({ 
            success: false, 
            message: 'Erro ao remover dispositivo' 
        });
    }
});

// Rota para ativar/desativar dispositivo
app.put('/api/devices/:imei', authMiddleware, async (req, res) => {
    try {
        const device = await Device.findOne({ imei: req.params.imei });
        
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
            device 
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            message: 'Erro ao atualizar dispositivo' 
        });
    }
});

// Rota para o painel admin
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Inicialização do servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor rodando na porta ${PORT}`);
    console.log(`Ambiente: ${process.env.NODE_ENV || 'desenvolvimento'}`);
});