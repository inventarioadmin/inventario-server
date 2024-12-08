// Salve isso como remove-encryption.js
require('dotenv').config();
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    role: String,
    isActive: Boolean
});

const User = mongoose.model('User', userSchema);

mongoose.connect(process.env.MONGODB_URI)
    .then(async () => {
        console.log('MongoDB conectado');
        
        await User.updateOne(
            { username: 'GreenSys' },
            { $set: { password: 'PlanADM042072@' } }
        );
        
        console.log('Senha atualizada com sucesso (sem criptografia)!');
        process.exit(0);
    })
    .catch(err => {
        console.error('Erro:', err);
        process.exit(1);
    });