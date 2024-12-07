require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const mongoURI = process.env.MONGODB_URI.includes('/?') 
    ? process.env.MONGODB_URI.replace('/?', '/inventario?')
    : process.env.MONGODB_URI;

const User = mongoose.model('User', {
    username: String,
    password: String,
    role: String,
    isActive: Boolean
});

async function createSuperAdmin() {
    try {
        console.log('Conectando ao MongoDB...');
        console.log('URI:', mongoURI.replace(/:[^:/@]+@/, ':****@')); // Oculta a senha no log
        
        await mongoose.connect(mongoURI);
        console.log('Conectado com sucesso!');

        // Define credenciais do super admin
        const username = 'GreenSys';
        const password = 'PlanADM042072@';

        // Remove super admin existente (se houver)
        await User.deleteOne({ role: 'superadmin' });
        console.log('Removido super admin antigo (se existia)');

        // Cria hash da senha
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Cria novo super admin
        const user = new User({
            username: username,
            password: hashedPassword,
            role: 'superadmin',
            isActive: true
        });

        await user.save();
        console.log('\n=== Super Admin criado com sucesso! ===');
        console.log('Username:', username);
        console.log('Senha:', password);
        console.log('Role: Super Admin');
        console.log('Status: Ativo');
        console.log('====================================\n');

    } catch (error) {
        console.error('Erro:', error);
    } finally {
        await mongoose.connection.close();
        console.log('Conexão fechada');
        process.exit(0);
    }
}

createSuperAdmin();