const mongoose = require("mongoose");

const wazuhAlertSchema = new mongoose.Schema(
  {
    ruleLevel: Number,
    ruleDescription: String,
    agentName: String,
    agentId: String,
    location: String,
    rawAlert: Object,
  },
  { timestamps: true }
);

module.exports = mongoose.model("WazuhAlert", wazuhAlertSchema);