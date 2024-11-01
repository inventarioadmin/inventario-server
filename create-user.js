// create-user.js
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const User = mongoose.model('User', {
    username: String,
    password: String,
    isAdmin: Boolean
});

async function createUser() {
    try {
        console.log('Conectando ao MongoDB...');
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Conectado!');

        const hashedPassword = await bcrypt.hash('PlanADM042072', 10);
        
        const user = new User({
            username: 'planforte',
            password: hashedPassword,
            isAdmin: true
        });

        await user.save();
        console.log('\n=== Usuário criado com sucesso! ===');
        console.log('Username: planforte');
        console.log('Senha: PlanADM042072');
        console.log('================================\n');

    } catch (error) {
        console.error('Erro:', error);
    } finally {
        await mongoose.connection.close();
        process.exit(0);
    }
}

createUser();