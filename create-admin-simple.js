// create-admin-simple.js
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

async function criarAdmin() {
    try {
        console.log('Conectando ao banco...');
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Conectado!');

        // Definir modelo
        const User = mongoose.model('User', {
            username: String,
            password: String,
            isAdmin: Boolean
        });

        // Criar senha
        const senha = 'admin123';
        const hashSenha = await bcrypt.hash(senha, 10);

        // Criar admin
        const admin = new User({
            username: 'admin',
            password: hashSenha,
            isAdmin: true
        });

        await admin.save();
        console.log('Admin criado com sucesso!');
        console.log('Username: admin');
        console.log('Senha: admin123');

        await mongoose.connection.close();
        console.log('Conexão fechada');

    } catch (error) {
        console.error('Erro:', error.message);
    }
}

criarAdmin();