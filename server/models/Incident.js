const mongoose = require("mongoose");

const incidentSchema = new mongoose.Schema(
  {
    incidentKey: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },

    tenant_id: {
      type: String,
      default: "tenant_1",
      index: true,
    },

    source: {
      type: String,
      default: "wazuh",
      index: true,
    },

    correlationId: {
      type: String,
      default: "",
      index: true,
    },

    parentIncidentId: {
      type: String,
      default: "",
    },

    relatedIncidents: {
      type: Array,
      default: [],
    },

    attackChain: {
      type: Array,
      default: [],
    },

    agentId: {
      type: String,
      default: "",
      index: true,
    },

    title: {
      type: String,
      default: "",
      index: true,
    },

    host: {
      type: String,
      default: "",
      index: true,
    },

    ip: {
      type: String,
      default: "",
      index: true,
    },

    os: {
      type: String,
      default: "",
    },

    hostname: {
      type: String,
      default: "",
    },

    domain: {
      type: String,
      default: "",
    },

    severity: {
      type: String,
      default: "Medium",
      index: true,
    },

    priority: {
      type: String,
      default: "P3",
      index: true,
    },

    tier: {
      type: String,
      default: "investigation",
      index: true,
    },

    incidentType: {
      type: String,
      default: "Investigation Incident",
      index: true,
    },

    verdict: {
      type: String,
      default: "needs_review",
      index: true,
    },

    aiConfidence: {
      type: Number,
      default: 0,
      index: true,
    },

    aiProvider: {
      type: String,
      default: "claude",
    },

    aiModel: {
      type: String,
      default: "",
    },

    aiReasoning: {
      type: String,
      default: "",
    },

    riskScore: {
      type: Number,
      default: 0,
      index: true,
    },

    riskFactors: {
      type: Array,
      default: [],
    },

    historicalMatches: {
      type: Number,
      default: 0,
    },

    falsePositiveRate: {
      type: Number,
      default: 0,
    },

    truePositiveCount: {
      type: Number,
      default: 0,
    },

    threatIntel: {
      type: mongoose.Schema.Types.Mixed,
      default: "none",
    },

    threatFeedHits: {
      type: Array,
      default: [],
    },

    maliciousIPs: {
      type: Array,
      default: [],
    },

    maliciousHashes: {
      type: Array,
      default: [],
    },

    suspiciousDomains: {
      type: Array,
      default: [],
    },

    enrichment: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },

    recommendedAction: {
      type: String,
      default: "",
    },

    recommendedActions: {
      type: Array,
      default: [],
    },

    soarActions: {
      type: Array,
      default: [],
    },

    executedActions: {
      type: Array,
      default: [],
    },

    blockedIPs: {
      type: Array,
      default: [],
    },

    isolatedHosts: {
      type: Array,
      default: [],
    },

    killedProcesses: {
      type: Array,
      default: [],
    },

    disabledUsers: {
      type: Array,
      default: [],
    },

    tickets: {
      type: Array,
      default: [],
    },

    lastSeen: {
      type: Date,
      default: Date.now,
      index: true,
    },

    firstSeen: {
      type: Date,
      default: Date.now,
      index: true,
    },

    status: {
      type: String,
      default: "Open",
      index: true,
    },

    assigned: {
      type: String,
      default: "",
    },

    assignedTeam: {
      type: String,
      default: "",
    },

    classification: {
      type: String,
      default: "Unclassified",
      index: true,
    },

    environment: {
      type: String,
      default: "production",
    },

    assetCriticality: {
      type: String,
      default: "MEDIUM",
      index: true,
    },

    complianceImpact: {
      type: Array,
      default: [],
    },

    escalationStatus: {
      type: String,
      default: "pending",
      index: true,
    },

    escalationLevel: {
      type: Number,
      default: 0,
    },

    requiresHumanReview: {
      type: Boolean,
      default: true,
      index: true,
    },

    autoCloseEligible: {
      type: Boolean,
      default: false,
    },

    suppressionCandidate: {
      type: Boolean,
      default: false,
    },

    autoSuppressed: {
      type: Boolean,
      default: false,
    },

    learningEligible: {
      type: Boolean,
      default: true,
    },

    aiQualityIssue: {
      type: Boolean,
      default: false,
    },

    detectionGap: {
      type: Boolean,
      default: false,
    },

    relatedAlerts: {
      type: Array,
      default: [],
    },

    evidence: {
      type: Array,
      default: [],
    },

    playbooks: {
      type: Array,
      default: [],
    },

    timeline: {
      type: Array,
      default: [],
    },

    notes: {
      type: Array,
      default: [],
    },

    analystNotes: {
      type: Array,
      default: [],
    },

    mitreTechniques: {
      type: Array,
      default: [],
      index: true,
    },

    mitreTactics: {
      type: Array,
      default: [],
    },

    indicators: {
      type: Array,
      default: [],
    },

    iocs: {
      type: Array,
      default: [],
    },

    hashes: {
      type: Array,
      default: [],
    },

    urls: {
      type: Array,
      default: [],
    },

    domains: {
      type: Array,
      default: [],
    },

    emails: {
      type: Array,
      default: [],
    },

    processes: {
      type: Array,
      default: [],
    },

     parentApplications: {
  type: Array,
  default: [],
},

notifications: {
  type: Array,
  default: [],
},

    processTree: {
      type: Array,
      default: [],
    },


    users: {
      type: Array,
      default: [],
    },

    lateralMovementEvidence: {
      type: Array,
      default: [],
    },

    networkConnections: {
      type: Array,
      default: [],
    },

    sourceIPs: {
      type: Array,
      default: [],
    },

    destinationIPs: {
      type: Array,
      default: [],
    },

    geoLocations: {
      type: Array,
      default: [],
    },

    attackSurface: {
      type: Array,
      default: [],
    },

    tags: {
      type: Array,
      default: [],
      index: true,
    },

    closedAt: {
      type: Date,
      default: null,
    },

    closedBy: {
      type: String,
      default: "",
    },

    resolution: {
      type: String,
      default: "",
    },

    resolutionCategory: {
      type: String,
      default: "",
    },

    dwellTimeMinutes: {
      type: Number,
      default: 0,
    },

    investigationDurationMinutes: {
      type: Number,
      default: 0,
    },
  },
  {
    timestamps: true,
  }
);

incidentSchema.index({
  severity: 1,
  status: 1,
  lastSeen: -1,
});

incidentSchema.index({
  host: 1,
  incidentType: 1,
});

incidentSchema.index({
  riskScore: -1,
});

incidentSchema.index({
  verdict: 1,
});

incidentSchema.index({
  indicators: 1,
});

incidentSchema.index({
  users: 1,
});

incidentSchema.index({
  processes: 1,
});


module.exports = mongoose.model(
  "Incident",
  incidentSchema
);