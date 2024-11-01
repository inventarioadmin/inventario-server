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
        await mongoose.connect(process.env.MONGODB_URI);
        
        // Verifica se já existe
        let admin = await User.findOne({ username: 'planforte' });
        
        if (admin) {
            console.log('Atualizando senha do admin existente...');
            admin.password = await bcrypt.hash('PlanADM042072', 10);
            await admin.save();
        } else {
            console.log('Criando novo admin...');
            admin = new User({
                username: 'planforte',
                password: await bcrypt.hash('PlanADM042072', 10),
                isAdmin: true
            });
            await admin.save();
        }
        
        console.log('Admin criado/atualizado com sucesso!');
        console.log('Username: planforte');
        console.log('Senha: PlanADM042072');
        
    } catch (error) {
        console.error('Erro:', error);
    } finally {
        await mongoose.connection.close();
    }
}

createAdmin();