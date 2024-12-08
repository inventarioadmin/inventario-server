// models/Device.js
const mongoose = require('mongoose');

const deviceSchema = new mongoose.Schema({
    androidId: {
        type: String,
        required: true,
        unique: true
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
        default: null
    },
    lastAccess: {
        type: Date,
        default: null
    }
}, { timestamps: true });

module.exports = mongoose.model('Device', deviceSchema);