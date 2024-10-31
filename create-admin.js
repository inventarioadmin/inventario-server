// create-admin.js
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// Verificar variáveis de ambiente
console.log('Verificando configurações...');
if (!process.env.MONGODB_URI) {
    console.error('Erro: MONGODB_URI não encontrada no arquivo .env');
    process.exit(1);
}

console.log('MongoDB URI:', process.env.MONGODB_URI.substring(0, 20) + '...');

// Schema do usuário
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false }
});

const User = mongoose.model('User', userSchema);

async function createAdmin() {
    let connection;
    try {
        console.log('Conectando ao MongoDB...');
        connection = await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        console.log('Conectado ao MongoDB com sucesso!');

        // Verificar se já existe um admin
        console.log('Verificando se já existe um admin...');
        const existingAdmin = await User.findOne({ username: 'admin' });
        if (existingAdmin) {
            console.log('Admin já existe! Criando novo hash de senha...');
        }

        // Criar hash da senha
        console.log('Criando hash da senha...');
        const password = 'admin123';
        const hashedPassword = await bcrypt.hash(password, 10);
        console.log('Hash da senha criado com sucesso!');

        // Criar ou atualizar admin
        const adminUser = {
            username: 'admin',
            password: hashedPassword,
            isAdmin: true
        };

        if (existingAdmin) {
            console.log('Atualizando senha do admin existente...');
            await User.updateOne({ username: 'admin' }, adminUser);
            console.log('Admin atualizado com sucesso!');
        } else {
            console.log('Criando novo usuário admin...');
            const admin = new User(adminUser);
            await admin.save();
            console.log('Novo admin criado com sucesso!');
        }

        console.log('\n=== ADMIN CRIADO/ATUALIZADO COM SUCESSO ===');
        console.log('Username: admin');
        console.log('Senha: admin123');
        console.log('=======================================\n');

    } catch (error) {
        console.error('\nERRO AO CRIAR ADMIN:');
        console.error('Tipo do erro:', error.name);
        console.error('Mensagem:', error.message);
        if (error.code === 11000) {
            console.error('Erro de duplicidade: usuário já existe');
        }
        console.error('\nStack trace:', error.stack);
    } finally {
        if (connection) {
            console.log('Fechando conexão com o MongoDB...');
            await mongoose.connection.close();
            console.log('Conexão fechada!');
        }
        process.exit(0);
    }
}

// Executar a função
console.log('Iniciando criação do admin...\n');
createAdmin();