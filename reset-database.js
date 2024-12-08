require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const mongoURI = process.env.MONGODB_URI.includes('/?') 
    ? process.env.MONGODB_URI.replace('/?', '/inventario?')
    : process.env.MONGODB_URI;

async function resetDatabase() {
    try {
        console.log('Conectando ao MongoDB...');
        await mongoose.connect(mongoURI);
        console.log('Conectado com sucesso!');

        // Limpa todas as coleções
        console.log('\nLimpando banco de dados...');
        await mongoose.connection.db.collection('users').deleteMany({});
        await mongoose.connection.db.collection('companies').deleteMany({});
        await mongoose.connection.db.collection('devices').deleteMany({});
        console.log('Banco de dados limpo!');

        // Cria super admin
        const hashedPassword = await bcrypt.hash('PlanADM042072@', 10);
        const superAdmin = {
            username: 'GreenSys',
            password: hashedPassword,
            role: 'superadmin',
            isActive: true,
            createdAt: new Date(),
            updatedAt: new Date()
        };

        await mongoose.connection.db.collection('users').insertOne(superAdmin);
        console.log('\nSuper Admin criado:');
        console.log('Username:', superAdmin.username);
        console.log('Role:', superAdmin.role);

        // Verifica se foi criado corretamente
        console.log('\nVerificando usuários criados:');
        const users = await mongoose.connection.db.collection('users').find({}).toArray();
        users.forEach(user => {
            console.log(`- ${user.username} (${user.role})`);
        });

    } catch (error) {
        console.error('Erro:', error);
    } finally {
        await mongoose.connection.close();
        console.log('\nConexão fechada');
        process.exit(0);
    }
}

resetDatabase();