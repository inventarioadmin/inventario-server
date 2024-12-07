require('dotenv').config();
const mongoose = require('mongoose');

const mongoURI = process.env.MONGODB_URI.includes('/?') 
    ? process.env.MONGODB_URI.replace('/?', '/inventario?')
    : process.env.MONGODB_URI;

async function testFind() {
    try {
        console.log('Conectando ao MongoDB...');
        await mongoose.connect(mongoURI);
        console.log('Conectado com sucesso!');

        // Define o modelo
        const User = mongoose.model('User', new mongoose.Schema({
            username: String,
            password: String,
            role: String,
            isActive: Boolean
        }, { collection: 'users' }));

        // Tenta buscar o usuário de diferentes formas
        console.log('\nTentando diferentes buscas...');
        
        console.log('\n1. Buscando por username:');
        const user1 = await User.findOne({ username: 'superadmin' });
        console.log('Resultado:', user1);

        console.log('\n2. Listando todos os usuários:');
        const allUsers = await User.find({});
        console.log('Total de usuários:', allUsers.length);
        allUsers.forEach(u => console.log('- Username:', u.username, 'Role:', u.role));

        console.log('\n3. Buscando por role:');
        const user2 = await User.findOne({ role: 'superadmin' });
        console.log('Resultado:', user2);

        // Tenta buscar diretamente na coleção
        console.log('\n4. Buscando diretamente na coleção:');
        const directResult = await mongoose.connection.db.collection('users').findOne({ username: 'superadmin' });
        console.log('Resultado direto:', directResult);

    } catch (error) {
        console.error('Erro:', error);
    } finally {
        await mongoose.connection.close();
        console.log('\nConexão fechada');
        process.exit(0);
    }
}

testFind();