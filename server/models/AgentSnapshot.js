const mongoose = require("mongoose");

const agentSnapshotSchema = new mongoose.Schema(
  {
    agentId: String,
    incidentKey: String,
    host: String,
    ip: String,
    os: String,
    status: String,
    lastSeen: String,
    riskScore: Number,
    severity: String,
    priority: String,
    tier: String,
    assetType: String,
    wazuhLevel: Number,
    riskBreakdown: Object,
  },
  { timestamps: true }
);

module.exports = mongoose.model("AgentSnapshot", agentSnapshotSchema);