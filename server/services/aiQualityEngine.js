const Incident = require("../models/Incident");
const AlertPattern = require("../models/AlertPattern");

const HIGH_CONFIDENCE_THRESHOLD = 0.9;
const WRONG_AI_THRESHOLD = 3;
const UNSTABLE_VERDICT_THRESHOLD = 3;

function normalizeVerdict(verdict = "") {
  if (verdict === "tp") return "true_positive";
  if (verdict === "fp") return "false_positive";
  if (verdict === "investigate") return "needs_investigation";
  if (verdict === "needs_review") return "needs_investigation";
  return verdict || "needs_review";
}

function isDisagreement(aiVerdict, analystDecision) {
  if (!aiVerdict || !analystDecision) return false;
  return normalizeVerdict(aiVerdict) !== normalizeVerdict(analystDecision);
}

function calculateAiQualityScore(pattern = {}) {
  let score = 100;

  const wrong = Number(pattern.ai_wrong_count || 0);
  const correct = Number(pattern.ai_correct_count || 0);
  const total = wrong + correct;

  if (total > 0) {
    const wrongRate = wrong / total;
    score -= wrongRate * 60;
  }

  if (wrong >= WRONG_AI_THRESHOLD) {
    score -= 20;
  }

  if (pattern.ai_quality_risk) {
    score -= 20;
  }

  return Math.max(0, Math.round(score));
}

function detectUnstableVerdicts(pattern = {}) {
  const lastAi = normalizeVerdict(pattern.last_ai_verdict || "");
  const lastAnalyst = normalizeVerdict(pattern.last_analyst_decision || "");

  return Boolean(lastAi && lastAnalyst && lastAi !== lastAnalyst);
}

function shouldCreateAiQualityIncident(pattern = {}) {
  const wrong = Number(pattern.ai_wrong_count || 0);
  const confidence = Number(pattern.last_confidence || 0);

  return (
    wrong >= WRONG_AI_THRESHOLD ||
    (confidence >= HIGH_CONFIDENCE_THRESHOLD && detectUnstableVerdicts(pattern))
  );
}

function buildAiQualityReason(pattern = {}) {
  const reasons = [];

  if (Number(pattern.ai_wrong_count || 0) >= WRONG_AI_THRESHOLD) {
    reasons.push("AI has repeated wrong predictions");
  }

  if (Number(pattern.last_confidence || 0) >= HIGH_CONFIDENCE_THRESHOLD) {
    reasons.push("AI produced high-confidence decision requiring review");
  }

  if (detectUnstableVerdicts(pattern)) {
    reasons.push("AI and analyst verdicts disagree");
  }

  if (reasons.length === 0) {
    reasons.push("AI quality monitored");
  }

  return reasons.join(", ");
}

async function updateAiQualityFromDecision({
  patternKey,
  aiVerdict,
  analystDecision,
  aiConfidence = 0,
  analyst = "system",
  alert = null,
}) {
  if (!patternKey) return null;

  const pattern = await AlertPattern.findOne({ pattern_key: patternKey });

  if (!pattern) return null;

  const disagreement = isDisagreement(aiVerdict, analystDecision);

  if (disagreement) {
    pattern.ai_wrong_count = Number(pattern.ai_wrong_count || 0) + 1;
  } else {
    pattern.ai_correct_count = Number(pattern.ai_correct_count || 0) + 1;
  }

  const total =
    Number(pattern.ai_correct_count || 0) + Number(pattern.ai_wrong_count || 0);

  pattern.ai_accuracy_rate =
    total > 0 ? Number(pattern.ai_correct_count || 0) / total : 0;

  pattern.ai_quality_risk = shouldCreateAiQualityIncident(pattern);
  pattern.last_ai_verdict = normalizeVerdict(aiVerdict);
  pattern.last_analyst_decision = normalizeVerdict(analystDecision);
  pattern.last_confidence = Number(aiConfidence || pattern.last_confidence || 0);
  pattern.last_seen = new Date();

  await pattern.save();

  let qualityIncident = null;

  if (pattern.ai_quality_risk) {
    qualityIncident = await createOrUpdateAiQualityIncident({
      pattern,
      analyst,
      alert,
      disagreement,
    });
  }

  return {
    pattern,
    disagreement,
    aiQualityScore: calculateAiQualityScore(pattern),
    qualityIncident,
  };
}

async function createOrUpdateAiQualityIncident({
  pattern,
  analyst = "system",
  alert = null,
  disagreement = false,
}) {
  const incidentKey = `ai-quality-${pattern.pattern_key}`
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 180);

  const now = new Date();

  const title = `AI Quality Incident - ${pattern.rule_description || pattern.pattern_key}`;

  const timelineEvent = {
    time: now.toISOString(),
    type: "AI_QUALITY_REVIEW",
    actor: analyst,
    message: buildAiQualityReason(pattern),
    ai_wrong_count: pattern.ai_wrong_count,
    ai_correct_count: pattern.ai_correct_count,
    ai_accuracy_rate: pattern.ai_accuracy_rate,
    last_ai_verdict: pattern.last_ai_verdict,
    last_analyst_decision: pattern.last_analyst_decision,
    disagreement,
  };

  const evidence = {
    time: now.toISOString(),
    pattern_key: pattern.pattern_key,
    rule_description: pattern.rule_description,
    agent: pattern.agent,
    process: pattern.process,
    username: pattern.username,
    last_ai_verdict: pattern.last_ai_verdict,
    last_analyst_decision: pattern.last_analyst_decision,
    last_confidence: pattern.last_confidence,
    ai_wrong_count: pattern.ai_wrong_count,
    ai_correct_count: pattern.ai_correct_count,
    ai_accuracy_rate: pattern.ai_accuracy_rate,
    reason: buildAiQualityReason(pattern),
    alert_id: alert?._id ? String(alert._id) : "",
  };

  const existing = await Incident.findOne({ incidentKey });

  if (!existing) {
    return Incident.create({
      incidentKey,
      tenant_id: pattern.tenant_id || "tenant_1",
      source: "ai-quality-engine",
      title,
      host: pattern.agent || "",
      severity: "Medium",
      priority: "P3",
      tier: "ai_quality",
      incidentType: "AI Quality Incident",
      classification: "AI Quality Incident",
      verdict: "needs_investigation",
      aiConfidence: Number(pattern.last_confidence || 0),
      riskScore: 50,
      status: "Open",
      assigned: "",
      lastSeen: now,
      firstSeen: now,
      aiQualityIssue: true,
      requiresHumanReview: true,
      escalationStatus: "ai_quality_review",
      recommendedAction:
        "Review AI decision quality, compare analyst feedback, inspect prompt/context, and adjust rules or triage strategy.",
      evidence: [evidence],
      timeline: [timelineEvent],
      notes: [
        {
          time: now.toISOString(),
          analyst,
          note: buildAiQualityReason(pattern),
        },
      ],
      relatedAlerts: alert?._id ? [String(alert._id)] : [],
      tags: ["AI_QUALITY", "ANALYST_DISAGREEMENT"],
      riskFactors: disagreement ? ["AI_ANALYST_DISAGREEMENT"] : ["AI_MONITORING"],
      enrichment: {
        aiQuality: {
          score: calculateAiQualityScore(pattern),
          disagreement,
          unstableVerdicts: detectUnstableVerdicts(pattern),
          reason: buildAiQualityReason(pattern),
        },
      },
    });
  }

  existing.lastSeen = now;
  existing.aiConfidence = Number(pattern.last_confidence || existing.aiConfidence || 0);
  existing.aiQualityIssue = true;
  existing.requiresHumanReview = true;
  existing.escalationStatus = "ai_quality_review";
  existing.recommendedAction =
    "Review AI decision quality, compare analyst feedback, inspect prompt/context, and adjust rules or triage strategy.";

  existing.evidence = Array.isArray(existing.evidence) ? existing.evidence : [];
  existing.timeline = Array.isArray(existing.timeline) ? existing.timeline : [];
  existing.notes = Array.isArray(existing.notes) ? existing.notes : [];
  existing.relatedAlerts = Array.isArray(existing.relatedAlerts)
    ? existing.relatedAlerts
    : [];
  existing.tags = Array.isArray(existing.tags) ? existing.tags : [];
  existing.riskFactors = Array.isArray(existing.riskFactors)
    ? existing.riskFactors
    : [];

  existing.evidence.push(evidence);
  existing.timeline.push(timelineEvent);
  existing.notes.push({
    time: now.toISOString(),
    analyst,
    note: buildAiQualityReason(pattern),
  });

  if (alert?._id && !existing.relatedAlerts.includes(String(alert._id))) {
    existing.relatedAlerts.push(String(alert._id));
  }

  if (!existing.tags.includes("AI_QUALITY")) {
    existing.tags.push("AI_QUALITY");
  }

  if (disagreement && !existing.tags.includes("ANALYST_DISAGREEMENT")) {
    existing.tags.push("ANALYST_DISAGREEMENT");
  }

  if (disagreement && !existing.riskFactors.includes("AI_ANALYST_DISAGREEMENT")) {
    existing.riskFactors.push("AI_ANALYST_DISAGREEMENT");
  }

  existing.enrichment = {
    ...(existing.enrichment || {}),
    aiQuality: {
      score: calculateAiQualityScore(pattern),
      disagreement,
      unstableVerdicts: detectUnstableVerdicts(pattern),
      reason: buildAiQualityReason(pattern),
    },
  };

  await existing.save();
  return existing;
}

module.exports = {
  normalizeVerdict,
  isDisagreement,
  calculateAiQualityScore,
  detectUnstableVerdicts,
  shouldCreateAiQualityIncident,
  buildAiQualityReason,
  updateAiQualityFromDecision,
  createOrUpdateAiQualityIncident,
};