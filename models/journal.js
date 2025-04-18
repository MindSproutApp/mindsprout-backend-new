const mongoose = require('mongoose');

const journalSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  date: { type: String, required: true }, // e.g., "Thursday 10th April 25"
  type: { type: String, enum: ['daily', 'dream'], required: true },
  responses: { type: Object, required: true }, // { highlights: String, learned: String, ... }
  insight: { type: String, default: null } // Populated when "Gain Insights" is called
}, { timestamps: true });

module.exports = mongoose.model('Journal', journalSchema);