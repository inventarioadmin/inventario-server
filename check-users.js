require('dotenv').config();
const mongoose = require('mongoose');

const mongoURI = process.env.MONGODB_URI.includes('/?') 
    ? process.env.MONGODB_URI.replace('/?', '/inventario?')
    : process.env.MONGODB_URI;

async function checkUsers() {
    try {
        console.log('Conectando ao MongoDB...');
        await mongoose.connect(mongoURI);
        console.log('Conectado com sucesso!');

        // Verifica todos os usuários
        const users = await mongoose.connection.db.collection('users').find({}).toArray();
        
        console.log('\n=== Usuários encontrados ===');
        users.forEach(user => {
            console.log(`\nUsername: ${user.username}`);
            console.log(`Role: ${user.role}`);
            console.log(`Status: ${user.isActive ? 'Ativo' : 'Inativo'}`);
            console.log('------------------------');
        });

        // Verifica todas as empresas
        const companies = await mongoose.connection.db.collection('companies').find({}).toArray();
        
        console.log('\n=== Empresas encontradas ===');
        companies.forEach(company => {
            console.log(`\nNome: ${company.name}`);
            console.log(`Username: ${company.username}`);
            console.log(`Status: ${company.isActive ? 'Ativo' : 'Inativo'}`);
            console.log('------------------------');
        });

    } catch (error) {
        console.error('Erro:', error);
    } finally {
        await mongoose.connection.close();
        console.log('\nConexão fechada');
        process.exit(0);
    }
}

checkUsers();