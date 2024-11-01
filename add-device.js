// add-device.js
require('dotenv').config();
const mongoose = require('mongoose');

const Device = mongoose.model('Device', {
    imei: String,
    description: String,
    isActive: Boolean,
    lastLogin: Date,
    expirationDate: Date,
    createdAt: { type: Date, default: Date.now }
});

async function addDevice(imei, description, monthsValid) {
    try {
        console.log('Conectando ao MongoDB...');
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Conectado!');

        // Calcular data de expiração
        const expirationDate = new Date();
        expirationDate.setMonth(expirationDate.getMonth() + monthsValid);

        const device = new Device({
            imei: imei,
            description: description,
            isActive: true,
            expirationDate: expirationDate
        });

        await device.save();
        console.log('\n=== Dispositivo adicionado com sucesso! ===');
        console.log('IMEI:', imei);
        console.log('Descrição:', description);
        console.log('Expira em:', expirationDate.toLocaleDateString());
        console.log('======================================\n');

    } catch (error) {
        console.error('Erro:', error);
    } finally {
        await mongoose.connection.close();
        process.exit(0);
    }
}

// Substitua '123456789' pelo IMEI real do dispositivo
addDevice('864048069134421', 'Dispositivo de Teste1', 12);
addDevice('864048069134439', 'Dispositivo de Teste2', 12);