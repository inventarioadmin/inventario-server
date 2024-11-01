// create-first-admin.js
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

async function createAdmin() {
    try {
        console.log('Conectando ao MongoDB...');
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Conectado!');

        const User = mongoose.model('User', {
            username: String,
            password: String,
            isAdmin: Boolean
        });

        // Criar hash da senha
        const hashedPassword = await bcrypt.hash('admin123', 10);

        // Criar usuário admin
        const admin = new User({
            username: 'admin',
            password: hashedPassword,
            isAdmin: true
        });

        await admin.save();
        console.log('\n=== Admin criado com sucesso! ===');
        console.log('Username: admin');
        console.log('Senha: admin123');
        console.log('==============================\n');

    } catch (error) {
        console.error('Erro:', error);
    } finally {
        await mongoose.connection.close();
        process.exit(0);
    }
}

createAdmin();