const Incident = require("../models/Incident");

const AUTO_CLOSE_MIN_ALERTS = 5;
const AUTO_CLOSE_MIN_FP_RATE = 0.9;
const AUTO_CLOSE_MIN_CONFIDENCE = 0.9;

function normalizeVerdict(verdict = "") {
  if (verdict === "tp") return "true_positive";
  if (verdict === "fp") return "false_positive";
  if (verdict === "investigate") return "needs_investigation";
  if (verdict === "needs_review") return "needs_investigation";

  return verdict || "needs_review";
}

function hasThreatIntel(threatIntel) {
  if (!threatIntel) return false;

  if (typeof threatIntel === "string") {
    const value = threatIntel.toLowerCase();

    return (
      value !== "none" &&
      value !== "no malicious ioc found" &&
      value !== "clean" &&
      value !== "-"
    );
  }

  if (Array.isArray(threatIntel)) {
    return threatIntel.length > 0;
  }

  return false;
}

function calculateSuppressionScore(incident = {}) {
  let score = 0;

  const fpRate = Number(incident.fpRate || 0);

  const confidence = Number(
    incident.aiConfidence || 0
  );

  const relatedAlerts = Array.isArray(
    incident.relatedAlerts
  )
    ? incident.relatedAlerts.length
    : 0;

  const verdict = normalizeVerdict(
    incident.verdict
  );

  if (verdict === "false_positive") {
    score += 40;
  }

  if (fpRate >= 0.9) {
    score += 35;
  } else if (fpRate >= 0.7) {
    score += 20;
  }

  if (confidence >= 0.95) {
    score += 25;
  } else if (confidence >= 0.85) {
    score += 15;
  }

  if (relatedAlerts >= 10) {
    score += 20;
  } else if (relatedAlerts >= 5) {
    score += 10;
  }

  if (incident.severity === "Critical") {
    score -= 50;
  }

  if (incident.severity === "High") {
    score -= 30;
  }

  if (hasThreatIntel(incident.threatIntel)) {
    score -= 40;
  }

  if (
    Array.isArray(incident.tags) &&
    incident.tags.includes(
      "COMMAND_AND_CONTROL"
    )
  ) {
    score -= 40;
  }

  if (
    Array.isArray(incident.riskFactors) &&
    incident.riskFactors.includes(
      "CREDENTIAL_ACCESS"
    )
  ) {
    score -= 40;
  }

  if (incident.requiresHumanReview) {
    score -= 15;
  }

  return Math.max(score, 0);
}

function shouldSuppressIncident(
  incident = {}
) {
  const score =
    calculateSuppressionScore(incident);

  return score >= 70;
}

function shouldAutoCloseIncident(
  incident = {}
) {
  const relatedAlerts = Array.isArray(
    incident.relatedAlerts
  )
    ? incident.relatedAlerts.length
    : 0;

  const confidence = Number(
    incident.aiConfidence || 0
  );

  const fpRate = Number(
    incident.fpRate || 0
  );

  const verdict = normalizeVerdict(
    incident.verdict
  );

  if (incident.severity === "Critical")
    return false;

  if (incident.severity === "High")
    return false;

  if (incident.requiresHumanReview)
    return false;

  if (hasThreatIntel(incident.threatIntel))
    return false;

  if (
    Array.isArray(incident.tags) &&
    (
      incident.tags.includes(
        "COMMAND_AND_CONTROL"
      ) ||
      incident.tags.includes(
        "CREDENTIAL_ACCESS"
      ) ||
      incident.tags.includes(
        "LATERAL_MOVEMENT"
      )
    )
  ) {
    return false;
  }

  return (
    verdict === "false_positive" &&
    relatedAlerts >=
      AUTO_CLOSE_MIN_ALERTS &&
    fpRate >= AUTO_CLOSE_MIN_FP_RATE &&
    confidence >=
      AUTO_CLOSE_MIN_CONFIDENCE
  );
}

function buildSuppressionReason(
  incident = {}
) {
  const reasons = [];

  if (
    normalizeVerdict(incident.verdict) ===
    "false_positive"
  ) {
    reasons.push(
      "Repeated false-positive verdict"
    );
  }

  if (
    Number(incident.fpRate || 0) >= 0.9
  ) {
    reasons.push(
      "High false-positive rate"
    );
  }

  if (
    Number(incident.aiConfidence || 0) >=
    0.9
  ) {
    reasons.push(
      "High AI confidence"
    );
  }

  if (
    Array.isArray(incident.relatedAlerts) &&
    incident.relatedAlerts.length >= 5
  ) {
    reasons.push(
      "Repeated alert pattern"
    );
  }

  return reasons.join(", ");
}

async function evaluateSuppression(
  incidentId
) {
  const incident =
    await Incident.findById(incidentId);

  if (!incident) {
    return null;
  }

  const suppressionScore =
    calculateSuppressionScore(incident);

  incident.suppressionScore =
    suppressionScore;

  incident.suppressionCandidate =
    shouldSuppressIncident(incident);

  incident.autoCloseEligible =
    shouldAutoCloseIncident(incident);

  incident.suppressionReason =
    buildSuppressionReason(incident);

  if (
    incident.autoCloseEligible &&
    incident.status !== "Closed"
  ) {
    incident.status = "Closed";

    incident.closedAt = new Date();

    incident.closedBy =
      "suppression-engine";

    if (
      !Array.isArray(incident.timeline)
    ) {
      incident.timeline = [];
    }

    incident.timeline.push({
      time: new Date().toISOString(),
      type: "AUTO_CLOSED",
      actor: "suppression-engine",
      message:
        "Incident automatically closed by suppression engine due to repeated high-confidence false-positive behavior.",
    });
  }

  await incident.save();

  return incident;
}

module.exports = {
  calculateSuppressionScore,
  shouldSuppressIncident,
  shouldAutoCloseIncident,
  buildSuppressionReason,
  evaluateSuppression,
};