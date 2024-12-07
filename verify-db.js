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

async function verifyDatabase() {
    try {
        console.log('Conectando ao MongoDB...');
        await mongoose.connect(mongoURI);
        console.log('Conectado com sucesso!');

        // Listar todas as coleções
        const collections = await mongoose.connection.db.listCollections().toArray();
        console.log('\nColeções no banco:', collections.map(c => c.name));

        // Verificar usuários
        console.log('\nVerificando coleção de usuários...');
        const users = await User.find({});
        console.log('Total de usuários:', users.length);
        
        users.forEach(user => {
            console.log('\nUsuário encontrado:');
            console.log('Username:', user.username);
            console.log('Role:', user.role);
            console.log('Status:', user.isActive);
            console.log('ID:', user._id);
        });

    } catch (error) {
        console.error('Erro:', error);
    } finally {
        await mongoose.connection.close();
        console.log('\nConexão fechada');
        process.exit(0);
    }
}

verifyDatabase();