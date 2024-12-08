require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Company = require('./models/Company');
const Device = require('./models/Device');

// Schema do User
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['superadmin', 'admin'], required: true },
    companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company' },
    isActive: { type: Boolean, default: true }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

async function initialize() {
    try {
        // Conecta ao MongoDB
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Conectado ao MongoDB');

        // Verifica se já existe um superadmin
        const existingSuperAdmin = await User.findOne({ role: 'superadmin' });
        if (existingSuperAdmin) {
            console.log('Superadmin já existe!');
            console.log('Username:', existingSuperAdmin.username);
            return;
        }

        // Cria senha hash
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(process.env.SUPERADMIN_PASSWORD || 'admin123', salt);

        // Cria superadmin
        const superAdmin = new User({
            username: process.env.SUPERADMIN_USERNAME || 'superadmin',
            password: hashedPassword,
            role: 'superadmin',
            isActive: true
        });

        await superAdmin.save();
        console.log('Superadmin criado com sucesso!');
        console.log('Username:', superAdmin.username);
        console.log('Senha:', process.env.SUPERADMIN_PASSWORD || 'admin123');

        // Limpa dados de teste se estiver em ambiente de desenvolvimento
        if (process.env.NODE_ENV === 'development') {
            // Remove todos os dados exceto o superadmin
            await Company.deleteMany({});
            await Device.deleteMany({});
            await User.deleteMany({ role: { $ne: 'superadmin' } });
            
            console.log('Dados de teste limpos com sucesso!');
        }

    } catch (error) {
        console.error('Erro durante a inicialização:', error);
    } finally {
        await mongoose.disconnect();
        console.log('Desconectado do MongoDB');
    }
}

// Executa o script
initialize();