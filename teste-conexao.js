// teste-conexao.js
require('dotenv').config();
const mongoose = require('mongoose');

console.log('Iniciando teste de conexão...');
console.log('Verificando variáveis de ambiente:');
console.log('MONGODB_URI existe:', !!process.env.MONGODB_URI);
console.log('JWT_SECRET existe:', !!process.env.JWT_SECRET);
console.log('PORT existe:', !!process.env.PORT);

async function testarConexao() {
    try {
        console.log('\nTentando conectar ao MongoDB...');
        await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        console.log('Conexão estabelecida com sucesso!');
        
        // Testar operação básica
        const Test = mongoose.model('Test', { name: String });
        await Test.deleteMany({}); // Limpar testes anteriores
        
        console.log('\nTestando operações no banco...');
        const test = new Test({ name: 'teste_conexao' });
        await test.save();
        console.log('Operação de escrita: OK');
        
        const found = await Test.findOne({ name: 'teste_conexao' });
        console.log('Operação de leitura: OK');
        console.log('Documento encontrado:', found);
        
    } catch (error) {
        console.error('\nERRO NA CONEXÃO:');
        console.error('Tipo do erro:', error.name);
        console.error('Mensagem:', error.message);
        console.error('\nStack trace:', error.stack);
    } finally {
        if (mongoose.connection.readyState === 1) {
            await mongoose.connection.close();
            console.log('\nConexão fechada com sucesso');
        }
        process.exit(0);
    }
}

testarConexao();