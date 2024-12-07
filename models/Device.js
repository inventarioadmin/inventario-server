const mongoose = require('mongoose');

const deviceSchema = new mongoose.Schema({
    androidId: {
        type: String,
        required: true
    },
    imei: {
        type: String,
        sparse: true  // Permite múltiplos documentos com valor null
    },
    description: {
        type: String,
        required: true
    },
    companyId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Company',
        required: true
    },
    isActive: {
        type: Boolean,
        default: true
    },
    lastLogin: {
        type: Date,
        default: Date.now
    }
});

// Criar índices compostos para evitar duplicatas por empresa
deviceSchema.index({ androidId: 1, companyId: 1 }, { unique: true });

module.exports = mongoose.model('Device', deviceSchema);