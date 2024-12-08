// reset-superadmin.js
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// Schema do User
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['superadmin', 'admin'], required: true },
    isActive: { type: Boolean, default: true }
});

const User = mongoose.model('User', userSchema);

async function resetSuperAdmin() {
    try {
        // Conecta ao MongoDB
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Conectado ao MongoDB');

        // Busca o superadmin
        const superadmin = await User.findOne({ role: 'superadmin' });
        if (!superadmin) {
            console.log('Superadmin não encontrado!');
            return;
        }

        // Cria nova senha hash
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash('PlanADM042072@', salt);

        // Atualiza a senha
        superadmin.password = hashedPassword;
        await superadmin.save();

        console.log('Senha do Superadmin atualizada com sucesso!');
        console.log('Username:', superadmin.username);
        console.log('Nova senha: PlanADM042072@');

    } catch (error) {
        console.error('Erro:', error);
    } finally {
        await mongoose.disconnect();
        console.log('Desconectado do MongoDB');
    }
}

// Executa o script
resetSuperAdmin();