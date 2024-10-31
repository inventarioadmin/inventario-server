// create-admin.js
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const User = mongoose.model('User', {
    username: String,
    password: String,
    isAdmin: Boolean
});

async function createAdmin() {
    try {
        console.log('Conectando ao MongoDB...');
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Conectado!');

        const hashedPassword = await bcrypt.hash('admin123', 10);
        
        const admin = new User({
            username: 'admin',
            password: hashedPassword,
            isAdmin: true
        });

        await admin.save();
        console.log('Admin criado com sucesso!');
        console.log('Username: admin');
        console.log('Senha: admin123');

    } catch (error) {
        console.error('Erro:', error);
    } finally {
        await mongoose.connection.close();
    }
}

createAdmin();