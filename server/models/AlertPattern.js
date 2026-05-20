const mongoose = require("mongoose");

const alertPatternSchema = new mongoose.Schema(
  {
    pattern_key: {
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

    rule_description: {
      type: String,
      default: "",
    },

    rule_id: {
      type: String,
      default: "",
    },

    agent: {
      type: String,
      default: "",
    },

    agent_id: {
      type: String,
      default: "",
    },

    process: {
      type: String,
      default: "",
    },

    username: {
      type: String,
      default: "",
    },

    source_ip: {
      type: String,
      default: "",
    },

    destination_ip: {
      type: String,
      default: "",
    },

    mitre_ids: {
      type: Array,
      default: [],
    },

    mitre_techniques: {
      type: Array,
      default: [],
    },

    mitre_tactics: {
      type: Array,
      default: [],
    },

    occurrences: {
      type: Number,
      default: 0,
      index: true,
    },

    fp_count: {
      type: Number,
      default: 0,
    },

    tp_count: {
      type: Number,
      default: 0,
    },

    investigation_count: {
      type: Number,
      default: 0,
    },

    ai_correct_count: {
      type: Number,
      default: 0,
    },

    ai_wrong_count: {
      type: Number,
      default: 0,
    },

    fp_rate: {
      type: Number,
      default: 0,
      index: true,
    },

    tp_rate: {
      type: Number,
      default: 0,
    },

    ai_accuracy_rate: {
      type: Number,
      default: 0,
    },

    suppression_candidate: {
      type: Boolean,
      default: false,
      index: true,
    },

    auto_close_eligible: {
      type: Boolean,
      default: false,
      index: true,
    },

    dangerous_pattern: {
      type: Boolean,
      default: false,
      index: true,
    },

    ai_quality_risk: {
      type: Boolean,
      default: false,
      index: true,
    },

    last_ai_verdict: {
      type: String,
      default: "",
    },

    last_analyst_decision: {
      type: String,
      default: "",
    },

    last_confidence: {
      type: Number,
      default: 0,
    },

    last_risk: {
      type: Number,
      default: 0,
    },

    last_reason: {
      type: String,
      default: "",
    },

    last_seen: {
      type: Date,
      default: Date.now,
      index: true,
    },

    first_seen: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("AlertPattern", alertPatternSchema);