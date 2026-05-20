const mongoose = require("mongoose");

const analystDecisionSchema = new mongoose.Schema(
  {
    alert_id: {
      type: String,
      required: true,
      index: true,
    },

    incident_id: {
      type: String,
      default: "",
      index: true,
    },

    tenant_id: {
      type: String,
      default: "tenant_1",
      index: true,
    },

    decision: {
      type: String,
      enum: [
        "true_positive",
        "false_positive",
        "needs_investigation",
        "needs_review",
      ],
      required: true,
      index: true,
    },

    analyst: {
      type: String,
      default: "unknown",
      index: true,
    },

    reason: {
      type: String,
      default: "",
    },

    analyst_notes: {
      type: Array,
      default: [],
    },

    investigation_notes: {
      type: Array,
      default: [],
    },

    evidence_notes: {
      type: Array,
      default: [],
    },

    status: {
      type: String,
      enum: ["open", "resolved", "investigating", "closed", "escalated"],
      default: "open",
      index: true,
    },

    incident_type: {
      type: String,
      default: "",
      index: true,
    },

    severity: {
      type: String,
      default: "Medium",
    },

    priority: {
      type: String,
      default: "P3",
    },

    confidence: {
      type: Number,
      default: 0,
    },

    previous_confidence: {
      type: Number,
      default: 0,
    },

    confidence_adjustment: {
      type: Number,
      default: 0,
    },

    ai_correct: {
      type: Boolean,
      default: false,
    },

    ai_provider: {
      type: String,
      default: "claude",
    },

    ai_model: {
      type: String,
      default: "",
    },

    ai_verdict: {
      type: String,
      default: "",
    },

    ai_reasoning: {
      type: String,
      default: "",
    },

    ai_confidence: {
      type: Number,
      default: 0,
    },

    ai_risk_score: {
      type: Number,
      default: 0,
    },

    ai_quality_issue: {
      type: Boolean,
      default: false,
    },

    recommended_action: {
      type: String,
      default: "",
    },

    approved_playbooks: {
      type: Array,
      default: [],
    },

    blocked_playbooks: {
      type: Array,
      default: [],
    },

    requires_human_review: {
      type: Boolean,
      default: false,
    },

    threat_intel: {
      type: mongoose.Schema.Types.Mixed,
      default: "none",
    },

    historical_matches: {
      type: Number,
      default: 0,
    },

    fp_rate: {
      type: Number,
      default: 0,
    },

    asset_criticality: {
      type: String,
      default: "UNKNOWN",
    },

    escalation_required: {
      type: Boolean,
      default: false,
    },

    notification_sent: {
      type: Boolean,
      default: false,
    },

    finalized: {
      type: Boolean,
      default: false,
    },

    finalized_at: {
      type: Date,
      default: null,
    },

    assigned_to: {
      type: String,
      default: "",
    },

    raw_response: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("AnalystDecision", analystDecisionSchema);