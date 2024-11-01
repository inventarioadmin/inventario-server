// renew-license.js
async function renewDevice(imei, monthsToAdd) {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        
        const device = await Device.findOne({ imei });
        if (!device) {
            console.log('Dispositivo não encontrado');
            return;
        }

        // Adicionar meses a partir da data atual
        const newExpiration = new Date();
        newExpiration.setMonth(newExpiration.getMonth() + monthsToAdd);
        
        device.expirationDate = newExpiration;
        await device.save();

        console.log('Licença renovada com sucesso!');
        console.log('Nova data de expiração:', newExpiration.toLocaleDateString());

    } catch (error) {
        console.error('Erro:', error);
    } finally {
        await mongoose.connection.close();
    }
}

// Renovar por mais 12 meses
// Substitua '123456789' pelo IMEI real do dispositivo
renewDevice('123456789', 12); 