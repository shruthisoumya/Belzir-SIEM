const express = require("express");
const router = express.Router();

const WazuhAlert = require("../models/WazuhAlert");
const AnalystDecision = require("../models/AnalystDecision");
const AlertPattern = require("../models/AlertPattern");
const analyzeAlert = require("../services/triageEngine");
const { createOrUpdateIncident } = require("../services/incidentEngine");

const DEFAULT_TENANT_ID = "tenant_1";
const MAX_ANALYST_QUEUE_LIMIT = 200;
const MAX_WEBHOOK_ALERTS_LIMIT = 300;
const MAX_INCIDENTS_LITE_LIMIT = 300;
const TEXT_LIMIT = 800;

function toNumber(value, fallback = 0) {
const number = Number(value);
return Number.isFinite(number) ? number : fallback;
}

function safeString(value, fallback = "", max = TEXT_LIMIT) {
if (value === null || value === undefined || value === "") return fallback;

try {
return String(value).slice(0, max);
} catch (err) {
return fallback;
}
}

function safeArray(value, maxItems = 20) {
if (!Array.isArray(value)) return [];
return value.slice(0, maxItems).map((item) => safeString(item, "", 300));
}

function normalizeDecision(decision) {
const value = safeString(decision).toLowerCase();

if (value === "tp") return "true_positive";
if (value === "fp") return "false_positive";
if (value === "investigate") return "needs_investigation";
if (value === "needs_review") return "needs_investigation";
if (value === "true_positive") return "true_positive";
if (value === "false_positive") return "false_positive";
if (value === "needs_investigation") return "needs_investigation";

return "needs_investigation";
}

function compactThreatIntel(value) {
if (!value) return "none";

if (typeof value === "string") {
return safeString(value, "none", 500);
}

if (Array.isArray(value)) {
return safeArray(value, 20);
}

if (typeof value === "object") {
return {
verdict: safeString(value.verdict, "unknown", 100),
summary: safeString(value.summary, "", 500),
hits: safeArray(value.hits, 20),
malicious: Boolean(value.malicious),
};
}

return safeString(value, "none", 500);
}

function normalizeThreatIntel(value) {
const compact = compactThreatIntel(value);

if (!compact) return "none";
if (typeof compact === "string") return compact;

try {
return JSON.stringify(compact).slice(0, 1000);
} catch (err) {
return "none";
}
}

function hasThreatIntelHit(value) {
if (!value) return false;

if (typeof value === "object") {
if (Array.isArray(value)) return value.length > 0;
if (Array.isArray(value.hits)) return value.hits.length > 0;
if (value.malicious === true) return true;
if (value.verdict && safeString(value.verdict).toLowerCase() === "suspicious") {
return true;
}
}

const text = normalizeThreatIntel(value).toLowerCase().trim();

return (
text !== "none" &&
text !== "no malicious ioc found." &&
text !== "no malicious ioc found" &&
text !== "no hit" &&
text !== "no hits" &&
text !== "clean" &&
text !== "-"
);
}

function getRaw(alert = {}) {
return alert.rawAlert || alert.raw || {};
}

function getEventData(alert = {}) {
return getRaw(alert).data?.win?.eventdata || {};
}

function getAuditData(alert = {}) {
return getRaw(alert).data?.audit || {};
}

function getData(alert = {}) {
return getRaw(alert).data || {};
}

function getTenantId(req, alert = {}) {
return (
req.body?.tenant_id ||
req.body?.tenantId ||
req.headers["x-tenant-id"] ||
alert.tenant_id ||
alert.tenantId ||
alert.rawAlert?.tenant_id ||
alert.rawAlert?.tenantId ||
DEFAULT_TENANT_ID
);
}

function getAnalyst(req, fallback = "unknown") {
return (
req.body?.analyst ||
req.body?.analyst_email ||
req.body?.user ||
req.headers["x-analyst"] ||
req.headers["x-user-email"] ||
fallback
);
}

function getRuleId(alert = {}) {
const raw = getRaw(alert);
return safeString(raw.rule?.id || alert.ruleId || alert.rule?.id || "");
}

function getRuleLevel(alert = {}) {
const raw = getRaw(alert);
return toNumber(alert.ruleLevel || raw.rule?.level || alert.rule?.level || 0);
}

function getRuleDescription(alert = {}) {
const raw = getRaw(alert);
return safeString(
alert.ruleDescription ||
raw.rule?.description ||
alert.rule?.description ||
"Wazuh Alert",
"Wazuh Alert",
500
);
}

function getAgentId(alert = {}) {
const raw = getRaw(alert);
return safeString(alert.agentId || raw.agent?.id || alert.agent?.id || "");
}

function getAgentName(alert = {}) {
const raw = getRaw(alert);
return safeString(
alert.agentName || raw.agent?.name || alert.agent?.name || "-",
"-",
300
);
}

function getAgentIp(alert = {}) {
const raw = getRaw(alert);
return safeString(raw.agent?.ip || alert.agentIp || alert.ip || "-");
}

function getProcess(alert = {}) {
const raw = getRaw(alert);
const eventData = getEventData(alert);
const audit = getAuditData(alert);
const data = getData(alert);

return safeString(
eventData.processName ||
eventData.image ||
eventData.newProcessName ||
audit.exe ||
audit.command ||
data.process ||
data.command ||
raw.decoder?.name ||
"unknown",
"unknown",
500
);
}

function getCommandLine(alert = {}) {
const eventData = getEventData(alert);
const data = getData(alert);
const audit = getAuditData(alert);

return safeString(
eventData.commandLine ||
eventData.processCommandLine ||
data.commandLine ||
data.command_line ||
data.command ||
audit.command ||
"-",
"-",
800
);
}

function getParentApplication(alert = {}) {
const raw = getRaw(alert);
const eventData = getEventData(alert);

return safeString(
eventData.parentProcessName || eventData.parentImage || raw.decoder?.parent || "-",
"-",
500
);
}

function getUsername(alert = {}) {
const data = getData(alert);
const eventData = getEventData(alert);
const audit = getAuditData(alert);

return safeString(
eventData.targetUserName ||
eventData.subjectUserName ||
data.srcuser ||
data.dstuser ||
data.user ||
audit.uid ||
"-",
"-",
300
);
}

function getLocation(alert = {}) {
const raw = getRaw(alert);
return safeString(alert.location || raw.location || "-", "-", 500);
}

function getTimestamp(alert = {}) {
const raw = getRaw(alert);
return alert.timestamp || alert.createdAt || raw.timestamp || new Date();
}

function getPatternKey(alert = {}) {
const ruleDescription = getRuleDescription(alert);
const agentName = getAgentName(alert);
const process = getProcess(alert);

return ${ruleDescription}-${agentName}-${process}
.toLowerCase()
.replace(/[^a-z0-9]+/g, "-")
.replace(/^-|-$/g, "")
.slice(0, 500);
}

function getStatusFromDecision(decision) {
if (decision === "false_positive") return "resolved";
if (decision === "needs_investigation") return "investigating";
if (decision === "true_positive") return "open";
return "investigating";
}

function getSeverityFromRisk(risk) {
const value = toNumber(risk);

if (value >= 80) return "Critical";
if (value >= 60) return "High";
if (value >= 30) return "Medium";
return "Low";
}

function getRiskFromRuleLevel(ruleLevel) {
const level = toNumber(ruleLevel);
return Math.max(0, Math.min(100, Math.round((level / 15) * 100)));
}

function compactAi(ai = {}) {
const verdict = normalizeDecision(ai.verdict || ai.ai_verdict);

return {
verdict,
confidence: toNumber(ai.confidence ?? ai.ai_confidence, 0),
reasoning: safeString(ai.reasoning || ai.ai_reasoning || "", "", 1000),
recommended_action: safeString(
ai.recommended_action || ai.recommendedAction || "",
"",
1000
),
requires_human_review: Boolean(ai.requires_human_review),
historical_matches: toNumber(ai.historical_matches, 0),
threat_intel: compactThreatIntel(ai.threat_intel),
indicators: safeArray(ai.indicators, 30),
malicious_ips: safeArray(ai.malicious_ips, 20),
malicious_hashes: safeArray(ai.malicious_hashes, 20),
suspicious_domains: safeArray(ai.suspicious_domains, 20),
urls: safeArray(ai.urls, 20),
attack_patterns: safeArray(ai.attack_patterns, 20),
attack_chain: safeArray(ai.attack_chain, 20),
risk: toNumber(ai.risk ?? ai.riskScore, 0),
fp_rate: toNumber(ai.fp_rate, 0),
tp_count: toNumber(ai.tp_count, 0),
asset_criticality: safeString(ai.asset_criticality || "UNKNOWN", "UNKNOWN", 100),
ai_provider: safeString(ai.ai_provider || "unknown", "unknown", 100),
ai_model: safeString(ai.ai_model || process.env.CLAUDE_MODEL || "unknown", "unknown", 150),
cache_control_enabled: Boolean(ai.cache_control_enabled),
claude_rate_limited: Boolean(ai.claude_rate_limited),
pattern_key: safeString(ai.pattern_key || "", "", 500),
suppression_candidate: Boolean(ai.suppression_candidate),
auto_close_eligible: Boolean(ai.auto_close_eligible),
dangerous_pattern: Boolean(ai.dangerous_pattern),
routine_noise: Boolean(ai.routine_noise),
create_investigation_incident: ai.create_investigation_incident !== false,
};
}

function buildAiFromSavedDecision(savedDecision) {
if (!savedDecision) return null;

const rawResponse =
savedDecision.raw_response && typeof savedDecision.raw_response === "object"
? savedDecision.raw_response
: {};

const verdict = normalizeDecision(
savedDecision.decision || rawResponse.verdict || savedDecision.ai_verdict
);

return compactAi({
verdict,
confidence:
savedDecision.confidence ??
savedDecision.ai_confidence ??
rawResponse.confidence ??
0,
reasoning:
savedDecision.reason ||
savedDecision.ai_reasoning ||
rawResponse.reasoning ||
"",
recommended_action:
savedDecision.recommended_action ||
rawResponse.recommended_action ||
rawResponse.recommendedAction ||
"",
requires_human_review:
savedDecision.requires_human_review ??
rawResponse.requires_human_review ??
false,
historical_matches:
savedDecision.historical_matches ?? rawResponse.historical_matches ?? 0,
threat_intel:
savedDecision.threat_intel || rawResponse.threat_intel || "none",
indicators: rawResponse.indicators,
malicious_ips: rawResponse.malicious_ips,
malicious_hashes: rawResponse.malicious_hashes,
suspicious_domains: rawResponse.suspicious_domains,
urls: rawResponse.urls,
attack_patterns: rawResponse.attack_patterns,
attack_chain: rawResponse.attack_chain,
risk:
savedDecision.ai_risk_score ??
rawResponse.risk ??
rawResponse.riskScore ??
0,
fp_rate: savedDecision.fp_rate ?? rawResponse.fp_rate ?? 0,
tp_count: rawResponse.tp_count ?? 0,
asset_criticality:
savedDecision.asset_criticality ||
rawResponse.asset_criticality ||
rawResponse.assetCriticality ||
"UNKNOWN",
ai_provider:
savedDecision.ai_provider || rawResponse.ai_provider || "saved_decision",
ai_model:
savedDecision.ai_model ||
rawResponse.ai_model ||
process.env.CLAUDE_MODEL ||
"unknown",
cache_control_enabled: rawResponse.cache_control_enabled,
claude_rate_limited: rawResponse.claude_rate_limited,
pattern_key: rawResponse.pattern_key,
suppression_candidate: rawResponse.suppression_candidate,
auto_close_eligible: rawResponse.auto_close_eligible,
dangerous_pattern: rawResponse.dangerous_pattern,
routine_noise: rawResponse.routine_noise,
create_investigation_incident:
rawResponse.create_investigation_incident ??
savedDecision.requires_human_review ??
false,
});
}

function compactAlertForResponse(alert = {}) {
return {
id: String(alert._id || ""),
alert_id: String(alert._id || ""),
tenant_id: alert.tenant_id || alert.rawAlert?.tenant_id || DEFAULT_TENANT_ID,
rule_id: getRuleId(alert),
rule_level: getRuleLevel(alert),
rule_description: getRuleDescription(alert),
agent: getAgentName(alert),
agentName: getAgentName(alert),
agentId: getAgentId(alert),
agentIp: getAgentIp(alert),
process: getProcess(alert),
command_line: getCommandLine(alert),
username: getUsername(alert),
parent_application: getParentApplication(alert),
location: getLocation(alert),
timestamp: getTimestamp(alert),
createdAt: alert.createdAt,
};
}

function compactDecisionForResponse(decision = {}) {
return {
id: String(decision._id || ""),
alert_id: safeString(decision.alert_id || ""),
tenant_id: safeString(decision.tenant_id || DEFAULT_TENANT_ID),
decision: normalizeDecision(decision.decision),
analyst: safeString(decision.analyst || ""),
reason: safeString(decision.reason || "", "", 1000),
status: safeString(decision.status || ""),
confidence: toNumber(decision.confidence, 0),
previous_confidence: toNumber(decision.previous_confidence, 0),
confidence_adjustment: toNumber(decision.confidence_adjustment, 0),
ai_correct: Boolean(decision.ai_correct),
ai_verdict: normalizeDecision(decision.ai_verdict || decision.decision),
ai_reasoning: safeString(decision.ai_reasoning || "", "", 1000),
ai_confidence: toNumber(decision.ai_confidence, 0),
ai_risk_score: toNumber(decision.ai_risk_score, 0),
ai_quality_issue: Boolean(decision.ai_quality_issue),
recommended_action: safeString(decision.recommended_action || "", "", 1000),
requires_human_review: Boolean(decision.requires_human_review),
ai_provider: safeString(decision.ai_provider || "", "", 100),
ai_model: safeString(decision.ai_model || "", "", 150),
threat_intel: compactThreatIntel(decision.threat_intel),
historical_matches: toNumber(decision.historical_matches, 0),
fp_rate: toNumber(decision.fp_rate, 0),
asset_criticality: safeString(decision.asset_criticality || "UNKNOWN"),
escalation_required: Boolean(decision.escalation_required),
createdAt: decision.createdAt,
updatedAt: decision.updatedAt,
};
}

function compactPatternForResponse(pattern = {}) {
if (!pattern) return null;

return {
id: String(pattern._id || ""),
pattern_key: safeString(pattern.pattern_key || "", "", 500),
tenant_id: safeString(pattern.tenant_id || DEFAULT_TENANT_ID),
rule_description: safeString(pattern.rule_description || "", "", 500),
rule_id: safeString(pattern.rule_id || ""),
agent: safeString(pattern.agent || ""),
agent_id: safeString(pattern.agent_id || ""),
username: safeString(pattern.username || ""),
process: safeString(pattern.process || "", "", 500),
occurrences: toNumber(pattern.occurrences, 0),
fp_count: toNumber(pattern.fp_count, 0),
tp_count: toNumber(pattern.tp_count, 0),
investigation_count: toNumber(pattern.investigation_count, 0),
ai_correct_count: toNumber(pattern.ai_correct_count, 0),
ai_wrong_count: toNumber(pattern.ai_wrong_count, 0),
fp_rate: toNumber(pattern.fp_rate, 0),
tp_rate: toNumber(pattern.tp_rate, 0),
ai_accuracy_rate: toNumber(pattern.ai_accuracy_rate, 0),
suppression_candidate: Boolean(pattern.suppression_candidate),
auto_close_eligible: Boolean(pattern.auto_close_eligible),
dangerous_pattern: Boolean(pattern.dangerous_pattern),
ai_quality_risk: Boolean(pattern.ai_quality_risk),
last_seen: pattern.last_seen,
last_ai_verdict: normalizeDecision(pattern.last_ai_verdict),
last_analyst_decision: normalizeDecision(pattern.last_analyst_decision),
last_confidence: toNumber(pattern.last_confidence, 0),
last_risk: toNumber(pattern.last_risk, 0),
last_reason: safeString(pattern.last_reason || "", "", 1000),
createdAt: pattern.createdAt,
updatedAt: pattern.updatedAt,
};
}

function compactIncidentForResponse(incident = null) {
if (!incident) return null;

return {
id: String(incident._id || ""),
incidentKey: safeString(incident.incidentKey || ""),
title: safeString(incident.title || "", "", 500),
host: safeString(incident.host || ""),
severity: safeString(incident.severity || ""),
priority: safeString(incident.priority || ""),
tier: safeString(incident.tier || ""),
status: safeString(incident.status || ""),
riskScore: toNumber(incident.riskScore, 0),
verdict: normalizeDecision(incident.verdict),
aiConfidence: toNumber(incident.aiConfidence, 0),
recommendedAction: safeString(incident.recommendedAction || "", "", 1000),
createdAt: incident.createdAt,
updatedAt: incident.updatedAt,
lastSeen: incident.lastSeen,
};
}

function calculateAdjustedConfidence(ai, decision) {
const compact = compactAi(ai);
const aiConfidence = toNumber(compact.confidence, 0.5);
const aiVerdict = normalizeDecision(compact.verdict);

if (decision === "needs_investigation") {
return aiConfidence;
}

if (decision === aiVerdict) {
return Math.min(0.99, aiConfidence + 0.1);
}

if (decision === "false_positive" && aiVerdict === "true_positive") {
return Math.max(0.1, aiConfidence - 0.2);
}

if (decision === "true_positive" && aiVerdict === "false_positive") {
return Math.max(0.1, aiConfidence - 0.3);
}

return aiConfidence;
}

async function getOrCreatePattern(alert, tenantId = DEFAULT_TENANT_ID) {
const patternKey = getPatternKey(alert);

let pattern = await AlertPattern.findOne({
pattern_key: patternKey,
tenant_id: tenantId,
});

if (!pattern) {
pattern = await AlertPattern.create({
pattern_key: patternKey,
tenant_id: tenantId,
rule_description: getRuleDescription(alert),
rule_id: getRuleId(alert),
agent: getAgentName(alert),
agent_id: getAgentId(alert),
username: getUsername(alert),
process: getProcess(alert),
occurrences: 0,
fp_count: 0,
tp_count: 0,
investigation_count: 0,
ai_correct_count: 0,
ai_wrong_count: 0,
fp_rate: 0,
tp_rate: 0,
ai_accuracy_rate: 0,
suppression_candidate: false,
auto_close_eligible: false,
dangerous_pattern: false,
ai_quality_risk: false,
});
}

return pattern;
}

async function updatePatternLearning({ pattern, decision, ai, source = "analyst" }) {
const compact = compactAi(ai);
const aiVerdict = normalizeDecision(compact.verdict);
const aiConfidence = toNumber(compact.confidence, 0);

pattern.last_seen = new Date();
pattern.last_ai_verdict = aiVerdict;
pattern.last_analyst_decision = decision;
pattern.last_confidence = aiConfidence;
pattern.last_risk = toNumber(compact.risk, 0);
pattern.last_reason = safeString(compact.reasoning || "", "", 1000);

pattern.occurrences = toNumber(pattern.occurrences, 0) + 1;

if (decision === "needs_investigation") {
pattern.investigation_count = toNumber(pattern.investigation_count, 0) + 1;
}

if (decision === "false_positive") {
pattern.fp_count = toNumber(pattern.fp_count, 0) + 1;
}

if (decision === "true_positive") {
pattern.tp_count = toNumber(pattern.tp_count, 0) + 1;
pattern.dangerous_pattern = true;
}

if (source === "analyst") {
if (decision === aiVerdict) {
pattern.ai_correct_count = toNumber(pattern.ai_correct_count, 0) + 1;
} else if (decision !== "needs_investigation") {
pattern.ai_wrong_count = toNumber(pattern.ai_wrong_count, 0) + 1;
}
}

pattern.fp_rate =
toNumber(pattern.occurrences, 0) > 0
? toNumber(pattern.fp_count, 0) / toNumber(pattern.occurrences, 0)
: 0;

pattern.tp_rate =
toNumber(pattern.occurrences, 0) > 0
? toNumber(pattern.tp_count, 0) / toNumber(pattern.occurrences, 0)
: 0;

const totalAiJudged =
toNumber(pattern.ai_correct_count, 0) + toNumber(pattern.ai_wrong_count, 0);

pattern.ai_accuracy_rate =
totalAiJudged > 0 ? toNumber(pattern.ai_correct_count, 0) / totalAiJudged : 0;

const threatIntelHit = hasThreatIntelHit(compact.threat_intel);
const assetCriticality = compact.asset_criticality || "UNKNOWN";

pattern.suppression_candidate =
pattern.fp_rate > 0.9 && toNumber(pattern.occurrences, 0) > 50;

pattern.auto_close_eligible =
pattern.suppression_candidate === true &&
decision === "false_positive" &&
toNumber(compact.confidence, 0) > 0.85 &&
assetCriticality !== "HIGH" &&
threatIntelHit === false;

pattern.ai_quality_risk =
toNumber(pattern.ai_wrong_count, 0) >= 3 && toNumber(aiConfidence, 0) >= 0.9;

await pattern.save();
return pattern;
}

function shouldCreateIncident({ decision, ai, pattern }) {
const compact = compactAi(ai);

if (decision === "true_positive") return true;

if (decision === "needs_investigation") {
return compact.create_investigation_incident !== false;
}

if (pattern?.suppression_candidate === true) return true;

if (
toNumber(compact.confidence, 0) > 0.9 &&
normalizeDecision(compact.verdict) !== decision
) {
return true;
}

return false;
}

function buildAnalystQueueItem({ alert, savedDecision, pattern }) {
const compactAlert = compactAlertForResponse(alert);
const ai = buildAiFromSavedDecision(savedDecision);

const fallbackRisk = pattern?.last_risk ?? getRiskFromRuleLevel(compactAlert.rule_level);
const finalVerdict = normalizeDecision(
savedDecision?.decision || pattern?.last_ai_verdict || "needs_investigation"
);

const risk = toNumber(ai?.risk ?? fallbackRisk, 0);
const confidence = toNumber(
savedDecision?.confidence ?? ai?.confidence ?? pattern?.last_confidence ?? 0,
0
);

return {
alert_id: compactAlert.alert_id,
id: compactAlert.id,
tenant_id: compactAlert.tenant_id,

agent: compactAlert.agent,
agentName: compactAlert.agentName,
agentId: compactAlert.agentId,
agentIp: compactAlert.agentIp,

process: compactAlert.process,
command_line: compactAlert.command_line,
username: compactAlert.username,
parent_application: compactAlert.parent_application,

rule_description: compactAlert.rule_description,
rule_id: compactAlert.rule_id || "-",
rule_level: compactAlert.rule_level,
location: compactAlert.location,

pattern_key: getPatternKey(alert),

incident_type:
  finalVerdict === "true_positive"
    ? "Security Incident"
    : finalVerdict === "needs_investigation" &&
      (ai?.create_investigation_incident ?? true) !== false
    ? "Investigation Incident"
    : pattern?.suppression_candidate
    ? "Detection Tuning Incident"
    : null,

severity: getSeverityFromRisk(risk),
status: savedDecision?.status || getStatusFromDecision(finalVerdict),

verdict: finalVerdict,
confidence,
reasoning:
  safeString(savedDecision?.reason || ai?.reasoning || pattern?.last_reason || "", "", 1000),
recommended_action: safeString(
  savedDecision?.recommended_action || ai?.recommended_action || "",
  "",
  1000
),

risk,
riskScore: risk,

historical_matches: toNumber(
  savedDecision?.historical_matches ?? ai?.historical_matches ?? pattern?.occurrences,
  0
),
fp_rate: toNumber(savedDecision?.fp_rate ?? ai?.fp_rate ?? pattern?.fp_rate, 0),
tp_rate: toNumber(pattern?.tp_rate, 0),
threat_intel: compactThreatIntel(savedDecision?.threat_intel || ai?.threat_intel),

suppression_candidate: Boolean(pattern?.suppression_candidate || ai?.suppression_candidate),
auto_close_eligible: Boolean(pattern?.auto_close_eligible || ai?.auto_close_eligible),
dangerous_pattern: Boolean(pattern?.dangerous_pattern || ai?.dangerous_pattern),

analyst: savedDecision?.analyst || null,
analyst_reason: safeString(savedDecision?.reason || "", "", 1000),

requires_human_review:
  savedDecision?.requires_human_review ?? ai?.requires_human_review ?? finalVerdict !== "false_positive",

ai_provider: safeString(savedDecision?.ai_provider || ai?.ai_provider || "saved_decision"),
ai_model: safeString(savedDecision?.ai_model || ai?.ai_model || process.env.CLAUDE_MODEL || ""),
create_investigation_incident: ai?.create_investigation_incident ?? finalVerdict !== "false_positive",

timestamp: compactAlert.timestamp,
createdAt: compactAlert.createdAt,

};
}

router.post("/webhook-alert", async (req, res) => {
try {
const alert = req.body || {};
const tenantId = getTenantId(req, alert);

console.log("🚨 Incoming alert:", {
  tenant_id: tenantId,
  rule_id: alert.rule?.id,
  rule_level: alert.rule?.level,
  rule_description: safeString(alert.rule?.description, "", 300),
  agent: alert.agent?.name,
  location: alert.location,
});

const savedAlert = await WazuhAlert.create({
  tenant_id: tenantId,
  ruleLevel: alert.rule?.level,
  ruleDescription: alert.rule?.description,
  agentName: alert.agent?.name,
  agentId: alert.agent?.id,
  location: alert.location,
  timestamp: alert.timestamp ? new Date(alert.timestamp) : new Date(),
  rawAlert: {
    ...alert,
    tenant_id: tenantId,
  },
});

console.log("✅ Saved:", savedAlert._id);

let pattern = await getOrCreatePattern(savedAlert, tenantId);
const ai = compactAi(await analyzeAlert(savedAlert, pattern));

const aiDecision = normalizeDecision(ai.verdict);
const status = getStatusFromDecision(aiDecision);

const savedDecision = await AnalystDecision.create({
  alert_id: String(savedAlert._id),
  tenant_id: tenantId,
  decision: aiDecision,
  analyst: "claude",
  reason: ai.reasoning || "",
  status,
  confidence: toNumber(ai.confidence, 0),
  previous_confidence: 0,
  confidence_adjustment: 0,
  ai_correct: false,
  ai_verdict: aiDecision,
  ai_reasoning: ai.reasoning || "",
  ai_confidence: toNumber(ai.confidence, 0),
  ai_risk_score: toNumber(ai.risk, 0),
  ai_quality_issue: false,
  recommended_action: ai.recommended_action || "",
  requires_human_review:
    aiDecision === "needs_investigation" || ai.requires_human_review === true,
  ai_provider: ai.ai_provider || "claude",
  ai_model: ai.ai_model || process.env.CLAUDE_MODEL,
  threat_intel: compactThreatIntel(ai.threat_intel),
  historical_matches: toNumber(ai.historical_matches, 0),
  fp_rate: toNumber(ai.fp_rate, 0),
  asset_criticality: ai.asset_criticality || "UNKNOWN",
  escalation_required: aiDecision === "true_positive",
  raw_response: ai,
});

console.log("🤖 Claude decision saved:", savedDecision._id);

pattern = await updatePatternLearning({
  pattern,
  decision: aiDecision,
  ai: {
    ...ai,
    verdict: aiDecision,
  },
  source: "claude",
});

console.log("📊 Pattern learning updated:", pattern._id);

let incident = null;

if (shouldCreateIncident({ decision: aiDecision, ai, pattern })) {
  incident = await createOrUpdateIncident({
    alert: savedAlert,
    ai: {
      ...ai,
      tenant_id: tenantId,
      verdict: aiDecision,
    },
    pattern,
    analystDecision: aiDecision,
    analyst: "claude",
    analystNotes: ai.reasoning || "",
  });

  if (incident) {
    console.log("🚨 Incident created/updated:", incident._id);
  }
} else {
  console.log("✅ No incident created for low-risk/noisy alert:", savedAlert._id);
}

return res.json({
  message: "Saved, triaged by Claude, pattern updated, and incident evaluated",
  data: compactAlertForResponse(savedAlert),
  ai: {
    ...ai,
    tenant_id: tenantId,
    verdict: aiDecision,
  },
  decision: compactDecisionForResponse(savedDecision),
  pattern: compactPatternForResponse(pattern),
  incident: compactIncidentForResponse(incident),
});

} catch (err) {
console.error("❌ Save + Claude triage error:", err.message);

return res.status(500).json({
  error: "Failed to save and triage alert",
  details: err.message,
});

}
});

router.get("/webhook-alerts", async (req, res) => {
try {
const limit = Math.min(
Math.max(parseInt(req.query.limit, 10) || 100, 1),
MAX_WEBHOOK_ALERTS_LIMIT
);

const tenantId = req.query.tenant_id || req.headers["x-tenant-id"] || null;

const query = tenantId
  ? {
      $or: [
        { tenant_id: tenantId },
        { "rawAlert.tenant_id": tenantId },
        { tenantId },
      ],
    }
  : {};

console.log(`📥 Fetching latest ${limit} webhook alerts`);

const alerts = await WazuhAlert.find(query)
  .select(
    "tenant_id ruleLevel ruleDescription agentName agentId location timestamp createdAt rawAlert.rule rawAlert.agent rawAlert.location rawAlert.timestamp rawAlert.data.win.eventdata rawAlert.data.audit rawAlert.data.srcuser rawAlert.data.dstuser rawAlert.data.user rawAlert.decoder"
  )
  .sort({ createdAt: -1, _id: -1 })
  .limit(limit)
  .lean();

const compactAlerts = alerts.map(compactAlertForResponse);

console.log(`✅ Returned ${compactAlerts.length} compact alerts`);

return res.json(compactAlerts);

} catch (err) {
console.error("❌ Fetch error:", err.message);

return res.status(500).json({
  error: "Failed to fetch alerts",
  details: err.message,
});

}
});

router.get("/incidents-lite", async (req, res) => {
try {
console.log("📥 GET /incidents-lite called");

const limit = Math.min(
  Math.max(parseInt(req.query.limit, 10) || 100, 1),
  MAX_INCIDENTS_LITE_LIMIT
);

const tenantId = req.query.tenant_id || req.headers["x-tenant-id"] || null;

const query = tenantId
  ? {
      $or: [
        { tenant_id: tenantId },
        { "rawAlert.tenant_id": tenantId },
        { tenantId },
      ],
    }
  : {};

const alerts = await WazuhAlert.find(query)
  .select(
    "tenant_id ruleLevel ruleDescription agentName agentId location timestamp createdAt rawAlert.rule rawAlert.agent rawAlert.location rawAlert.timestamp rawAlert.data.win.eventdata rawAlert.data.audit rawAlert.data.srcuser rawAlert.data.dstuser rawAlert.data.user rawAlert.decoder rawAlert.predecoder"
  )
  .sort({ createdAt: -1, _id: -1 })
  .limit(limit)
  .lean();

const incidents = alerts.map((alert) => {
  const ruleLevel = getRuleLevel(alert);

  return {
    id: String(alert._id),
    alert_id: String(alert._id),
    tenant_id: alert.tenant_id || alert.rawAlert?.tenant_id || DEFAULT_TENANT_ID,

    incidentType: getRuleDescription(alert),
    process: getProcess(alert),
    username: getUsername(alert),
    parentApplication: getParentApplication(alert),
    agentName: getAgentName(alert),

    severity:
      ruleLevel >= 8
        ? "High"
        : ruleLevel >= 4
        ? "Medium"
        : "Low",

    ruleLevel,
    ruleId: getRuleId(alert) || "-",
    location: getLocation(alert),
    timestamp: getTimestamp(alert),
  };
});

console.log(`✅ Returning ${incidents.length} lite incidents`);

return res.json(incidents);

} catch (err) {
console.error("❌ incidents-lite error:", err.message);

return res.status(500).json({
  error: "Failed to fetch lite incidents",
  details: err.message,
});

}
});

router.get("/analyst-queue", async (req, res) => {
try {
const limit = Math.min(
Math.max(parseInt(req.query.limit,10)||50,1),
100
);

const tenantId =
req.query.tenant_id ||
req.headers["x-tenant-id"] ||
null;

const query = tenantId
? {
$or:[
{tenant_id:tenantId},
{"rawAlert.tenant_id":tenantId}
]
}
:{};

const alerts = await WazuhAlert.find(query)
.select(
`
tenant_id
ruleLevel
ruleDescription
agentName
agentId
location
timestamp
createdAt
rawAlert.rule.id
rawAlert.rule.level
rawAlert.rule.description
rawAlert.rule.mitre
rawAlert.agent.name
rawAlert.agent.id
rawAlert.data.srcuser
rawAlert.data.dstuser
rawAlert.data.user
rawAlert.data.audit.uid
rawAlert.data.win.eventdata.targetUserName
rawAlert.data.win.eventdata.subjectUserName
rawAlert.data.win.eventdata.processName
rawAlert.data.win.eventdata.image
`
)
.sort({createdAt:-1})
.limit(limit)
.lean();

const ids=alerts.map(a=>String(a._id));

const decisions=await AnalystDecision.find({
alert_id:{$in:ids}
})
.select(`
alert_id
decision
confidence
reason
status
recommended_action
historical_matches
fp_rate
createdAt
`)
.sort({createdAt:-1})
.lean();

const decisionMap={};

for(const d of decisions){
if(!decisionMap[d.alert_id]){
decisionMap[d.alert_id]=d;
}
}

const data=alerts.map(alert=>{

const raw=getRawAlert(alert);

const d=
decisionMap[String(alert._id)]||null;

const risk=
normalizeRisk(
alert.ruleLevel||
raw.rule?.level||
0
);

return{

id:String(alert._id),

alert_id:String(alert._id),

tenant_id:
alert.tenant_id||
DEFAULT_TENANT_ID,

title:
alert.ruleDescription||
raw.rule?.description||
"Wazuh Alert",

rule_id:
raw.rule?.id||"",

rule_level:
alert.ruleLevel||
raw.rule?.level||
0,

agent:
alert.agentName||
raw.agent?.name||
"-",

host:
alert.agentName||
raw.agent?.name||
"-",

location:
alert.location||
raw.location||
"-",

user:
extractUser(raw),

process:
extractProcess(raw),

verdict:
normalizeVerdict(
d?.decision||
"needs_investigation"
),

confidence:
normalizeConfidence(
d?.confidence||0
),

risk,

riskScore:risk,

severity:
getSeverityFromRisk(risk),

priority:
getPriorityFromSeverity(
getSeverityFromRisk(risk)
),

status:
d?.status||
"open",

reviewed:Boolean(d),

reasoning:
safeString(
d?.reason||
"-",
"-",
500
),

recommended_action:
safeString(
d?.recommended_action||
"-",
"-",
500
),

historical_matches:
d?.historical_matches||0,

fp_rate:
d?.fp_rate||0,

mitre:
extractMitre(raw),

timestamp:
alert.timestamp||
alert.createdAt,

createdAt:
alert.createdAt

};

});

return res.json({
data,
total:data.length
});

}catch(err){

console.error(
"analyst-queue error:",
err.message
);

return res.status(500).json({
error:"Failed analyst queue",
details:err.message
});

}
});

router.post("/analyst-decision", async (req, res) => {
try {
console.log("📥 POST /analyst-decision:", {
alert_id: req.body?.alert_id,
decision: req.body?.decision,
analyst: req.body?.analyst || req.body?.analyst_email || req.body?.user,
});

const { alert_id, reason } = req.body || {};
const decision = normalizeDecision(req.body?.decision);
const analyst = getAnalyst(req);

if (!alert_id || !decision) {
  return res.status(400).json({
    error: "alert_id and decision are required",
  });
}

const status = getStatusFromDecision(decision);

const alert = await WazuhAlert.findById(alert_id);

if (!alert) {
  return res.status(404).json({
    error: "Alert not found",
  });
}

const effectiveTenantId = getTenantId(req, alert);

let pattern = await getOrCreatePattern(alert, effectiveTenantId);
const ai = compactAi(await analyzeAlert(alert, pattern));
const adjustedConfidence = calculateAdjustedConfidence(ai, decision);
const aiVerdict = normalizeDecision(ai.verdict);

const savedDecision = await AnalystDecision.create({
  alert_id,
  tenant_id: effectiveTenantId,
  decision,
  analyst,
  reason: safeString(reason || "", "", 1000),
  status,
  confidence: adjustedConfidence,
  previous_confidence: toNumber(ai.confidence, 0),
  confidence_adjustment: adjustedConfidence - toNumber(ai.confidence, 0),
  ai_correct: decision === aiVerdict,
  ai_verdict: aiVerdict,
  ai_reasoning: ai.reasoning || "",
  ai_confidence: toNumber(ai.confidence, 0),
  ai_risk_score: toNumber(ai.risk, 0),
  ai_quality_issue: toNumber(ai.confidence, 0) > 0.9 && aiVerdict !== decision,
  recommended_action: ai.recommended_action || "",
  requires_human_review: decision === "needs_investigation",
  ai_provider: ai.ai_provider || "claude",
  ai_model: ai.ai_model || process.env.CLAUDE_MODEL,
  threat_intel: compactThreatIntel(ai.threat_intel),
  historical_matches: toNumber(ai.historical_matches, 0),
  fp_rate: toNumber(ai.fp_rate, 0),
  asset_criticality: ai.asset_criticality || "UNKNOWN",
  escalation_required: decision === "true_positive",
  raw_response: ai,
});

pattern = await updatePatternLearning({
  pattern,
  decision,
  ai,
  source: "analyst",
});

let incident = null;

if (shouldCreateIncident({ decision, ai, pattern })) {
  incident = await createOrUpdateIncident({
    alert,
    ai: {
      ...ai,
      tenant_id: effectiveTenantId,
      verdict: aiVerdict,
    },
    pattern,
    analystDecision: decision,
    analyst,
    analystNotes: safeString(reason || "", "", 1000),
  });

  if (incident) {
    console.log("🚨 Incident created/updated:", incident._id);
  }
}

return res.status(200).json({
  success: true,
  message:
    decision === "false_positive"
      ? "Pattern added for false-positive analysis"
      : decision === "true_positive"
      ? "Incident created and escalation initiated"
      : shouldCreateIncident({ decision, ai, pattern })
      ? "Investigation incident created"
      : "Low-risk noisy alert kept in triage without incident creation",
  data: {
    decision: compactDecisionForResponse(savedDecision),
    pattern: compactPatternForResponse(pattern),
    incident: compactIncidentForResponse(incident),
  },
  decision: compactDecisionForResponse(savedDecision),
  pattern: compactPatternForResponse(pattern),
  incident: compactIncidentForResponse(incident),
});

} catch (err) {
console.error("❌ analyst-decision error:", err.message);

return res.status(500).json({
  error: "Failed to store analyst decision",
  details: err.message,
});

}
});

router.get("/alert-patterns", async (req, res) => {
try {
const tenantId = req.query.tenant_id || req.headers["x-tenant-id"] || null;
const query = tenantId ? { tenant_id: tenantId } : {};

const patterns = await AlertPattern.find(query)
  .select(
    "pattern_key tenant_id rule_description rule_id agent agent_id username process occurrences fp_count tp_count investigation_count ai_correct_count ai_wrong_count fp_rate tp_rate ai_accuracy_rate suppression_candidate auto_close_eligible dangerous_pattern ai_quality_risk last_seen last_ai_verdict last_analyst_decision last_confidence last_risk last_reason createdAt updatedAt"
  )
  .sort({ updatedAt: -1, _id: -1 })
  .limit(100)
  .lean();

return res.json(patterns.map(compactPatternForResponse));

} catch (err) {
return res.status(500).json({
error: "Failed to fetch alert patterns",
details: err.message,
});
}
});

module.exports = router;