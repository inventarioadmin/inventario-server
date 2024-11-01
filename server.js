// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path'); // Adicionando importação do path

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
    imei: { type: String, required: true, unique: true },
    description: String,
    isActive: { type: Boolean, default: true },
    lastLogin: Date,
    expirationDate: { type: Date, required: true }, // Nova propriedade
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

// Rota de login
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

        device.lastLogin = new Date();
        await device.save();

        const token = jwt.sign(
            { userId: user._id, deviceId },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            authKey: token,
            isAdmin: false
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Erro interno do servidor'
        });
    }
});

// Rotas de dispositivos
// Rota para listar dispositivos
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

// Rota para adicionar dispositivo
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

// Rota para excluir dispositivo
app.delete('/api/devices/:imei', authMiddleware, async (req, res) => {
    try {
        if (!req.user.isAdmin) {
            return res.status(403).json({ message: 'Acesso negado' });
        }

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
        if (!req.user.isAdmin) {
            return res.status(403).json({ message: 'Acesso negado' });
        }
        const device = await Device.findOne({ imei: req.params.imei });
        if (!device) {
            return res.status(404).json({ message: 'Dispositivo não encontrado' });
        }
        device.isActive = !device.isActive;
        await device.save();
        res.json({ success: true, device });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Criar pasta public se não existir
const publicPath = path.join(__dirname, 'public');
if (!require('fs').existsSync(publicPath)) {
    require('fs').mkdirSync(publicPath);
}

// Rota para a página admin
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Rota padrão
app.get('/', (req, res) => {
    res.send('Servidor do Inventário Florestal está rodando!');
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor rodando na porta ${PORT}`);
    console.log(`Ambiente: ${process.env.NODE_ENV || 'desenvolvimento'}`);
});
app.get('/admin', (req, res) => {
    const filePath = path.join(__dirname, 'public', 'admin.html');
    console.log('Tentando servir arquivo:', filePath);
    console.log('Arquivo existe:', require('fs').existsSync(filePath));
    res.sendFile(filePath);
});

// E adicione um endpoint de teste
app.get('/test-admin', (req, res) => {
    res.send('Admin endpoint está funcionando!');
});
