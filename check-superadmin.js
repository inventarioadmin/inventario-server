require('dotenv').config();
const mongoose = require('mongoose');

const mongoURI = process.env.MONGODB_URI.includes('/?') 
    ? process.env.MONGODB_URI.replace('/?', '/inventario?')
    : process.env.MONGODB_URI;

const User = mongoose.model('User', {
    username: String,
    password: String,
    role: String,
    isActive: Boolean
});

async function checkSuperAdmin() {
    try {
        console.log('Conectando ao MongoDB...');
        await mongoose.connect(mongoURI);
        console.log('Conectado com sucesso!');

        console.log('\nProcurando usuários no banco...');
        const allUsers = await User.find({});
        console.log('Total de usuários:', allUsers.length);
        
        console.log('\nProcurando super admin...');
        const superAdmin = await User.findOne({ role: 'superadmin' });
        
        if (superAdmin) {
            console.log('\n=== Super Admin encontrado! ===');
            console.log('Username:', superAdmin.username);
            console.log('Role:', superAdmin.role);
            console.log('Status:', superAdmin.isActive ? 'Ativo' : 'Inativo');
            console.log('Password Hash:', superAdmin.password.substring(0, 10) + '...');
        } else {
            console.log('\nNenhum super admin encontrado no banco!');
        }

    } catch (error) {
        console.error('Erro:', error);
    } finally {
        await mongoose.connection.close();
        process.exit(0);
    }
}

checkSuperAdmin();