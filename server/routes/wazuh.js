const express = require("express");
const mongoose = require("mongoose");
const { getClaudeCacheStats } = require("../services/claudeService");
const WazuhAlert = require("../models/WazuhAlert");
const AnalystDecision = require("../models/AnalystDecision");
const AlertPattern = require("../models/AlertPattern");
const Incident = require("../models/Incident");

const analyzeAlert = require("../services/triageEngine");
const { createOrUpdateIncident } = require("../services/incidentEngine");

const router = express.Router();

const DEFAULT_TENANT_ID = "tenant_1";
const MAX_LIMIT = 500;
const TEXT_LIMIT = 1000;

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

function safeArray(value, maxItems = 20, maxText = 300) {
  if (!Array.isArray(value)) return [];
  return value.slice(0, maxItems).map((item) => safeString(item, "", maxText));
}

function normalizeDecision(value) {
  const decision = safeString(value).toLowerCase();

  if (decision === "tp") return "true_positive";
  if (decision === "fp") return "false_positive";
  if (decision === "investigate") return "needs_investigation";
  if (decision === "needs_review") return "needs_investigation";
  if (decision === "true_positive") return "true_positive";
  if (decision === "false_positive") return "false_positive";
  if (decision === "needs_investigation") return "needs_investigation";

  return "needs_investigation";
}

function normalizeConfidence(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return 0;
  if (number > 1) return Math.max(0, Math.min(0.99, number / 100));
  return Math.max(0, Math.min(0.99, number));
}

function normalizeRisk(value) {
  const risk = Number(value);
  if (!Number.isFinite(risk)) return 0;
  return Math.max(0, Math.min(100, Math.round(risk)));
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

function getRawAlert(alert = {}) {
  return alert.rawAlert || alert.raw || {};
}

function getRuleId(alert = {}) {
  const raw = getRawAlert(alert);
  return safeString(alert.ruleId || alert.rule_id || raw.rule?.id || alert.rule?.id || "");
}

function getRuleLevel(alert = {}) {
  const raw = getRawAlert(alert);
  return toNumber(alert.ruleLevel || alert.rule_level || raw.rule?.level || alert.rule?.level || 0);
}

function getRuleDescription(alert = {}) {
  const raw = getRawAlert(alert);
  return safeString(
    alert.ruleDescription ||
      alert.rule_description ||
      raw.rule?.description ||
      alert.rule?.description ||
      "Wazuh Alert",
    "Wazuh Alert",
    500
  );
}

function getAgentName(alert = {}) {
  const raw = getRawAlert(alert);
  return safeString(alert.agentName || alert.agent || raw.agent?.name || alert.agent?.name || "-", "-", 300);
}

function getAgentId(alert = {}) {
  const raw = getRawAlert(alert);
  return safeString(alert.agentId || alert.agent_id || raw.agent?.id || alert.agent?.id || "");
}

function getAgentIp(alert = {}) {
  const raw = getRawAlert(alert);
  return safeString(alert.agentIp || alert.ip || raw.agent?.ip || "-", "-", 100);
}

function getLocation(alert = {}) {
  const raw = getRawAlert(alert);
  return safeString(alert.location || raw.location || "-", "-", 300);
}

function getData(alert = {}) {
  return getRawAlert(alert).data || {};
}

function getEventData(alert = {}) {
  return getRawAlert(alert).data?.win?.eventdata || {};
}

function getAuditData(alert = {}) {
  return getRawAlert(alert).data?.audit || {};
}

function getProcess(alert = {}) {
  const raw = getRawAlert(alert);
  const data = getData(alert);
  const eventData = getEventData(alert);
  const audit = getAuditData(alert);

  return safeString(
    alert.process ||
      eventData.processName ||
      eventData.image ||
      eventData.newProcessName ||
      eventData.originalFileName ||
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
  const data = getData(alert);
  const eventData = getEventData(alert);
  const audit = getAuditData(alert);

  return safeString(
    alert.command_line ||
      alert.commandLine ||
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
  const raw = getRawAlert(alert);
  const eventData = getEventData(alert);

  return safeString(
    alert.parent_application ||
      eventData.parentProcessName ||
      eventData.parentImage ||
      raw.decoder?.parent ||
      "-",
    "-",
    500
  );
}

function getUsername(alert = {}) {
  const data = getData(alert);
  const eventData = getEventData(alert);
  const audit = getAuditData(alert);

  return safeString(
    alert.username ||
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

function getTimestamp(alert = {}) {
  const raw = getRawAlert(alert);
  return alert.timestamp || alert.createdAt || raw.timestamp || new Date();
}

function getPatternKey(alert = {}) {
  return `${getRuleDescription(alert)}-${getAgentName(alert)}-${getProcess(alert)}`
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 500);
}

function getStatusFromDecision(decision) {
  const value = normalizeDecision(decision);

  if (value === "false_positive") return "closed";
  if (value === "needs_investigation") return "investigating";
  if (value === "true_positive") return "open";

  return "investigating";
}

function getSeverityFromRisk(risk) {
  const value = normalizeRisk(risk);

  if (value >= 80) return "Critical";
  if (value >= 60) return "High";
  if (value >= 30) return "Medium";

  return "Low";
}

function getPriorityFromSeverity(severity) {
  if (severity === "Critical") return "P1";
  if (severity === "High") return "P2";
  if (severity === "Medium") return "P3";
  return "P4";
}

function getRiskFromRuleLevel(ruleLevel) {
  const level = toNumber(ruleLevel);
  return Math.max(0, Math.min(100, Math.round((level / 15) * 100)));
}

function compactThreatIntel(value) {
  if (!value) return "none";

  if (typeof value === "string") {
    return safeString(value, "none", 500);
  }

  if (Array.isArray(value)) {
    return safeArray(value, 20, 300);
  }

  if (typeof value === "object") {
    return {
      verdict: safeString(value.verdict, "unknown", 100),
      summary: safeString(value.summary, "", 500),
      hits: safeArray(value.hits, 20, 300),
      malicious: Boolean(value.malicious),
    };
  }

  return safeString(value, "none", 500);
}

function hasThreatIntelHit(value) {
  if (!value) return false;

  if (Array.isArray(value)) return value.length > 0;

  if (typeof value === "object") {
    if (Array.isArray(value.hits)) return value.hits.length > 0;
    if (value.malicious === true) return true;
    if (value.verdict && safeString(value.verdict).toLowerCase() !== "clean") return true;
    return false;
  }

  const text = safeString(value).toLowerCase().trim();

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

function extractMitre(rawAlert = {}) {
  const mitre = rawAlert.rule?.mitre || rawAlert.mitre || {};

  return {
    ids: Array.isArray(mitre.id) ? mitre.id : mitre.id ? [mitre.id] : [],
    techniques: Array.isArray(mitre.technique)
      ? mitre.technique
      : mitre.technique
      ? [mitre.technique]
      : [],
    tactics: Array.isArray(mitre.tactic)
      ? mitre.tactic
      : mitre.tactic
      ? [mitre.tactic]
      : [],
  };
}

function extractHashes(rawAlert = {}) {
  const values = [
    rawAlert.data?.win?.eventdata?.hashes,
    rawAlert.data?.win?.eventdata?.hash,
    rawAlert.data?.hash,
    rawAlert.data?.sha256,
    rawAlert.data?.md5,
    rawAlert.syscheck?.sha256_after,
    rawAlert.syscheck?.md5_after,
  ];

  const hashes = [];

  values.forEach((value) => {
    if (!value) return;

    if (typeof value === "string") {
      value
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean)
        .forEach((item) => hashes.push(item));
    }

    if (Array.isArray(value)) {
      value.filter(Boolean).forEach((item) => hashes.push(item));
    }
  });

  return [...new Set(hashes)].slice(0, 30);
}

function extractNetwork(rawAlert = {}) {
  const values = [
    rawAlert.data?.srcip,
    rawAlert.data?.dstip,
    rawAlert.data?.srcport,
    rawAlert.data?.dstport,
    rawAlert.data?.protocol,
    rawAlert.data?.win?.eventdata?.ipAddress,
    rawAlert.data?.win?.eventdata?.sourceIp,
    rawAlert.data?.win?.eventdata?.destinationIp,
    rawAlert.data?.win?.eventdata?.sourcePort,
    rawAlert.data?.win?.eventdata?.destinationPort,
  ];

  return [...new Set(values.filter(Boolean).map(String))].slice(0, 30);
}

function extractIoCs(rawAlert = {}) {
  let text = "";

  try {
    text = JSON.stringify(rawAlert).slice(0, 20000);
  } catch (err) {
    text = "";
  }

  return {
    ips: [...new Set(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [])].slice(0, 30),
    urls: [...new Set(text.match(/https?:\/\/[^\s"]+/g) || [])].slice(0, 30),
    domains: [...new Set(text.match(/\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g) || [])].slice(0, 30),
    hashes: [...new Set(text.match(/\b[a-fA-F0-9]{32,64}\b/g) || [])].slice(0, 30),
  };
}

function detectAttackPatterns(rawAlert = {}) {
  let text = "";

  try {
    text = JSON.stringify(rawAlert).toLowerCase().slice(0, 20000);
  } catch (err) {
    text = "";
  }

  const patterns = [];

  if (
    text.includes("authentication failed") ||
    text.includes("failed password") ||
    text.includes("brute force") ||
    text.includes("invalid user")
  ) {
    patterns.push("BRUTE_FORCE");
  }

  if (
    text.includes("powershell") ||
    text.includes("encodedcommand") ||
    text.includes("invoke-expression") ||
    text.includes("iex")
  ) {
    patterns.push("POWERSHELL_ATTACK");
  }

  if (
    text.includes("mimikatz") ||
    text.includes("credential dumping") ||
    text.includes("lsass")
  ) {
    patterns.push("CREDENTIAL_ACCESS");
  }

  if (
    text.includes("psexec") ||
    text.includes("wmic") ||
    text.includes("remote execution") ||
    text.includes("lateral movement")
  ) {
    patterns.push("LATERAL_MOVEMENT");
  }

  if (
    text.includes("c2") ||
    text.includes("command and control") ||
    text.includes("reverse shell") ||
    text.includes("beacon")
  ) {
    patterns.push("COMMAND_AND_CONTROL");
  }

  if (
    text.includes("malware") ||
    text.includes("trojan") ||
    text.includes("ransomware")
  ) {
    patterns.push("MALWARE");
  }

  if (text.includes("persistence") || text.includes("scheduled task")) {
    patterns.push("PERSISTENCE");
  }

  return [...new Set(patterns)];
}

function compactAi(ai = {}) {
  const verdict = normalizeDecision(ai.verdict || ai.ai_verdict);

  return {
    verdict,
    confidence: normalizeConfidence(ai.confidence ?? ai.ai_confidence ?? 0),
    reasoning: safeString(ai.reasoning || ai.ai_reasoning || "", "", 1000),
    recommended_action: safeString(
      ai.recommended_action || ai.recommendedAction || "",
      "",
      1000
    ),
    requires_human_review: Boolean(ai.requires_human_review),
    historical_matches: toNumber(ai.historical_matches, 0),
    threat_intel: compactThreatIntel(ai.threat_intel),
    indicators: safeArray(ai.indicators, 30, 300),
    malicious_ips: safeArray(ai.malicious_ips, 20, 300),
    malicious_hashes: safeArray(ai.malicious_hashes, 20, 300),
    suspicious_domains: safeArray(ai.suspicious_domains, 20, 300),
    urls: safeArray(ai.urls, 20, 300),
    attack_patterns: safeArray(ai.attack_patterns, 20, 300),
    attack_chain: safeArray(ai.attack_chain, 20, 300),
    risk: normalizeRisk(ai.risk ?? ai.riskScore ?? 0),
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

  return compactAi({
    verdict: savedDecision.decision || rawResponse.verdict || savedDecision.ai_verdict,
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
    risk:
      savedDecision.ai_risk_score ??
      rawResponse.risk ??
      rawResponse.riskScore ??
      0,
    fp_rate: savedDecision.fp_rate ?? rawResponse.fp_rate ?? 0,
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
    host: getAgentName(alert),
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
    confidence: normalizeConfidence(decision.confidence),
    previous_confidence: normalizeConfidence(decision.previous_confidence),
    confidence_adjustment: toNumber(decision.confidence_adjustment, 0),
    ai_correct: Boolean(decision.ai_correct),
    ai_verdict: normalizeDecision(decision.ai_verdict || decision.decision),
    ai_reasoning: safeString(decision.ai_reasoning || "", "", 1000),
    ai_confidence: normalizeConfidence(decision.ai_confidence),
    ai_risk_score: normalizeRisk(decision.ai_risk_score),
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
    patternKey: safeString(pattern.pattern_key || "", "", 500),
    tenant_id: safeString(pattern.tenant_id || DEFAULT_TENANT_ID),
    rule_description: safeString(pattern.rule_description || "", "", 500),
    ruleDescription: safeString(pattern.rule_description || "", "", 500),
    rule_id: safeString(pattern.rule_id || ""),
    ruleId: safeString(pattern.rule_id || ""),
    agent: safeString(pattern.agent || ""),
    agentName: safeString(pattern.agent || ""),
    agent_id: safeString(pattern.agent_id || ""),
    username: safeString(pattern.username || ""),
    process: safeString(pattern.process || "", "", 500),
    occurrences: toNumber(pattern.occurrences, 0),
    fp_count: toNumber(pattern.fp_count, 0),
    fpCount: toNumber(pattern.fp_count, 0),
    tp_count: toNumber(pattern.tp_count, 0),
    tpCount: toNumber(pattern.tp_count, 0),
    investigation_count: toNumber(pattern.investigation_count, 0),
    investigationCount: toNumber(pattern.investigation_count, 0),
    ai_correct_count: toNumber(pattern.ai_correct_count, 0),
    aiCorrectCount: toNumber(pattern.ai_correct_count, 0),
    ai_wrong_count: toNumber(pattern.ai_wrong_count, 0),
    aiWrongCount: toNumber(pattern.ai_wrong_count, 0),
    fp_rate: toNumber(pattern.fp_rate, 0),
    fpRate: toNumber(pattern.fp_rate, 0),
    tp_rate: toNumber(pattern.tp_rate, 0),
    tpRate: toNumber(pattern.tp_rate, 0),
    ai_accuracy_rate: toNumber(pattern.ai_accuracy_rate, 0),
    aiAccuracyRate: toNumber(pattern.ai_accuracy_rate, 0),
    suppression_candidate: Boolean(pattern.suppression_candidate),
    suppressionCandidate: Boolean(pattern.suppression_candidate),
    auto_close_eligible: Boolean(pattern.auto_close_eligible),
    autoCloseEligible: Boolean(pattern.auto_close_eligible),
    dangerous_pattern: Boolean(pattern.dangerous_pattern),
    dangerousPattern: Boolean(pattern.dangerous_pattern),
    ai_quality_risk: Boolean(pattern.ai_quality_risk),
    aiQualityRisk: Boolean(pattern.ai_quality_risk),
    last_seen: pattern.last_seen,
    lastSeen: pattern.last_seen,
    last_ai_verdict: normalizeDecision(pattern.last_ai_verdict),
    lastAiVerdict: normalizeDecision(pattern.last_ai_verdict),
    last_analyst_decision: normalizeDecision(pattern.last_analyst_decision),
    lastAnalystDecision: normalizeDecision(pattern.last_analyst_decision),
    last_confidence: normalizeConfidence(pattern.last_confidence),
    lastConfidence: normalizeConfidence(pattern.last_confidence),
    last_risk: normalizeRisk(pattern.last_risk),
    lastRisk: normalizeRisk(pattern.last_risk),
    last_reason: safeString(pattern.last_reason || "", "", 1000),
    lastReason: safeString(pattern.last_reason || "", "", 1000),
    createdAt: pattern.createdAt,
    updatedAt: pattern.updatedAt,
  };
}

function compactIncidentForResponse(incident = null) {
  if (!incident) return null;

  return {
    id: String(incident._id || ""),
    _id: String(incident._id || ""),
    incidentKey: safeString(incident.incidentKey || ""),
    title: safeString(incident.title || "", "", 500),
    host: safeString(incident.host || ""),
    ip: safeString(incident.ip || ""),
    severity: safeString(incident.severity || ""),
    priority: safeString(incident.priority || ""),
    tier: safeString(incident.tier || ""),
    status: safeString(incident.status || ""),
    classification: safeString(incident.classification || incident.incidentType || ""),
    riskScore: normalizeRisk(incident.riskScore),
    verdict: normalizeDecision(incident.verdict),
    aiConfidence: normalizeConfidence(incident.aiConfidence),
    recommendedAction: safeString(incident.recommendedAction || "", "", 1000),
    relatedAlertCount: Array.isArray(incident.relatedAlerts) ? incident.relatedAlerts.length : 0,
    evidenceCount: Array.isArray(incident.evidence) ? incident.evidence.length : 0,
    createdAt: incident.createdAt,
    updatedAt: incident.updatedAt,
    lastSeen: incident.lastSeen,
  };
}

function buildAnalystQueueItem({ alert, savedDecision, pattern }) {
  const compactAlert = compactAlertForResponse(alert);
  const ai = buildAiFromSavedDecision(savedDecision);

  const finalVerdict = normalizeDecision(
    savedDecision?.decision || pattern?.last_ai_verdict || "needs_investigation"
  );

  const fallbackRisk = pattern?.last_risk ?? getRiskFromRuleLevel(compactAlert.rule_level);
  const risk = normalizeRisk(ai?.risk ?? fallbackRisk);

  const confidence = normalizeConfidence(
    savedDecision?.confidence ?? ai?.confidence ?? pattern?.last_confidence ?? 0
  );

  return {
    alert_id: compactAlert.alert_id,
    id: compactAlert.id,
    tenant_id: compactAlert.tenant_id,

    title: compactAlert.rule_description,
    rule_description: compactAlert.rule_description,
    ruleDescription: compactAlert.rule_description,
    rule_id: compactAlert.rule_id || "-",
    ruleId: compactAlert.rule_id || "-",
    rule_level: compactAlert.rule_level,
    ruleLevel: compactAlert.rule_level,

    agent: compactAlert.agent,
    agentName: compactAlert.agentName,
    agentId: compactAlert.agentId,
    agentIp: compactAlert.agentIp,
    host: compactAlert.agentName,

    process: compactAlert.process,
    command_line: compactAlert.command_line,
    commandLine: compactAlert.command_line,
    username: compactAlert.username,
    user: compactAlert.username,
    parent_application: compactAlert.parent_application,
    location: compactAlert.location,

    pattern_key: getPatternKey(alert),
    patternKey: getPatternKey(alert),

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
    priority: getPriorityFromSeverity(getSeverityFromRisk(risk)),
    status: savedDecision?.status || getStatusFromDecision(finalVerdict),

    verdict: finalVerdict,
    confidence,
    confidencePercent: Math.round(confidence * 100),

    reasoning: safeString(
      savedDecision?.reason || ai?.reasoning || pattern?.last_reason || "",
      "-",
      1000
    ),
    recommended_action: safeString(
      savedDecision?.recommended_action || ai?.recommended_action || "",
      "-",
      1000
    ),
    recommendedAction: safeString(
      savedDecision?.recommended_action || ai?.recommended_action || "",
      "-",
      1000
    ),

    risk,
    riskScore: risk,

    historical_matches: toNumber(
      savedDecision?.historical_matches ?? ai?.historical_matches ?? pattern?.occurrences,
      0
    ),
    historicalMatches: toNumber(
      savedDecision?.historical_matches ?? ai?.historical_matches ?? pattern?.occurrences,
      0
    ),

    fp_rate: toNumber(savedDecision?.fp_rate ?? ai?.fp_rate ?? pattern?.fp_rate, 0),
    fpRate: toNumber(savedDecision?.fp_rate ?? ai?.fp_rate ?? pattern?.fp_rate, 0),
    tp_rate: toNumber(pattern?.tp_rate, 0),
    tpRate: toNumber(pattern?.tp_rate, 0),

    threat_intel: compactThreatIntel(savedDecision?.threat_intel || ai?.threat_intel),
    threatIntel: compactThreatIntel(savedDecision?.threat_intel || ai?.threat_intel),

    suppression_candidate: Boolean(pattern?.suppression_candidate || ai?.suppression_candidate),
    suppressionCandidate: Boolean(pattern?.suppression_candidate || ai?.suppression_candidate),
    auto_close_eligible: Boolean(pattern?.auto_close_eligible || ai?.auto_close_eligible),
    autoCloseEligible: Boolean(pattern?.auto_close_eligible || ai?.auto_close_eligible),
    dangerous_pattern: Boolean(pattern?.dangerous_pattern || ai?.dangerous_pattern),
    dangerousPattern: Boolean(pattern?.dangerous_pattern || ai?.dangerous_pattern),

    analyst: savedDecision?.analyst || null,
    analyst_reason: safeString(savedDecision?.reason || "", "", 1000),

    requires_human_review:
      savedDecision?.requires_human_review ?? ai?.requires_human_review ?? finalVerdict !== "false_positive",
    requiresHumanReview:
      savedDecision?.requires_human_review ?? ai?.requires_human_review ?? finalVerdict !== "false_positive",

    ai_provider: safeString(savedDecision?.ai_provider || ai?.ai_provider || "saved_decision"),
    aiProvider: safeString(savedDecision?.ai_provider || ai?.ai_provider || "saved_decision"),
    ai_model: safeString(savedDecision?.ai_model || ai?.ai_model || process.env.CLAUDE_MODEL || ""),
    aiModel: safeString(savedDecision?.ai_model || ai?.ai_model || process.env.CLAUDE_MODEL || ""),

    create_investigation_incident:
      ai?.create_investigation_incident ?? finalVerdict !== "false_positive",

    timestamp: compactAlert.timestamp,
    createdAt: compactAlert.createdAt,
  };
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
      first_seen: new Date(),
      last_seen: new Date(),
    });
  }

  return pattern;
}

async function updatePatternLearning({ pattern, decision, ai, source = "analyst" }) {
  const compact = compactAi(ai);
  const aiVerdict = normalizeDecision(compact.verdict);
  const aiConfidence = normalizeConfidence(compact.confidence);

  pattern.last_seen = new Date();
  pattern.last_ai_verdict = aiVerdict;
  pattern.last_analyst_decision = decision;
  pattern.last_confidence = aiConfidence;
  pattern.last_risk = normalizeRisk(compact.risk);
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
    aiConfidence > 0.85 &&
    assetCriticality !== "HIGH" &&
    threatIntelHit === false;

  pattern.ai_quality_risk =
    toNumber(pattern.ai_wrong_count, 0) >= 3 && aiConfidence >= 0.9;

  await pattern.save();
  return pattern;
}

function calculateAdjustedConfidence(ai, decision) {
  const compact = compactAi(ai);
  const aiConfidence = normalizeConfidence(compact.confidence);
  const aiVerdict = normalizeDecision(compact.verdict);

  if (decision === "needs_investigation") return aiConfidence;
  if (decision === aiVerdict) return Math.min(0.99, aiConfidence + 0.1);
  if (decision === "false_positive" && aiVerdict === "true_positive") {
    return Math.max(0.1, aiConfidence - 0.2);
  }
  if (decision === "true_positive" && aiVerdict === "false_positive") {
    return Math.max(0.1, aiConfidence - 0.3);
  }

  return aiConfidence;
}

function shouldCreateIncident({ decision, ai, pattern }) {
  const compact = compactAi(ai);

  if (decision === "true_positive") return true;

  if (decision === "needs_investigation") {
    return compact.create_investigation_incident !== false;
  }

  if (pattern?.suppression_candidate === true) return true;

  if (
    normalizeConfidence(compact.confidence) > 0.9 &&
    normalizeDecision(compact.verdict) !== decision
  ) {
    return true;
  }

  return false;
}

async function findAlertById(alertId) {
  const orQuery = [{ alert_id: alertId }, { alertId }, { id: alertId }];

  if (mongoose.Types.ObjectId.isValid(alertId)) {
    orQuery.push({ _id: alertId });
  }

  return WazuhAlert.findOne({ $or: orQuery }).lean();
}

async function findLatestDecision(alert) {
  if (!alert) return null;

  const alertIds = [String(alert._id), alert.alert_id, alert.alertId, alert.id].filter(Boolean);

  return AnalystDecision.findOne({
    alert_id: { $in: alertIds.map(String) },
  })
    .sort({ createdAt: -1 })
    .lean();
}

async function findRelatedAlerts(rawAlert, limit = 20) {
  const agentName = rawAlert.agent?.name;
  const agentId = rawAlert.agent?.id;
  const user = getUsername({ rawAlert });
  const process = getProcess({ rawAlert });
  const srcip = rawAlert.data?.srcip;
  const dstip = rawAlert.data?.dstip;
  const mitre = extractMitre(rawAlert);

  const orQuery = [];

  if (agentName) orQuery.push({ agentName });
  if (agentId) orQuery.push({ agentId });

  if (user && user !== "-") {
    orQuery.push({ "rawAlert.data.srcuser": user });
    orQuery.push({ "rawAlert.data.dstuser": user });
    orQuery.push({ "rawAlert.data.user": user });
    orQuery.push({ "rawAlert.data.win.eventdata.targetUserName": user });
    orQuery.push({ "rawAlert.data.win.eventdata.subjectUserName": user });
  }

  if (process && process !== "-") {
    orQuery.push({ "rawAlert.data.win.eventdata.processName": process });
    orQuery.push({ "rawAlert.data.win.eventdata.image": process });
    orQuery.push({ "rawAlert.data.audit.exe": process });
  }

  if (srcip) orQuery.push({ "rawAlert.data.srcip": srcip });
  if (dstip) orQuery.push({ "rawAlert.data.dstip": dstip });

  mitre.ids.forEach((id) => {
    orQuery.push({ "rawAlert.rule.mitre.id": id });
  });

  if (orQuery.length === 0) return [];

  const related = await WazuhAlert.find({ $or: orQuery })
    .sort({ createdAt: -1 })
    .limit(limit)
    .select(
      "tenant_id ruleLevel ruleDescription agentName agentId location timestamp createdAt rawAlert.rule.id rawAlert.rule.level rawAlert.rule.description rawAlert.agent.name rawAlert.agent.id"
    )
    .lean();

  return related.map(compactAlertForResponse);
}

function buildAlertEvidence(alert) {
  const rawAlert = getRawAlert(alert);
  const mitre = extractMitre(rawAlert);
  const hashes = extractHashes(rawAlert);
  const network = extractNetwork(rawAlert);
  const iocs = extractIoCs(rawAlert);
  const attackPatterns = detectAttackPatterns(rawAlert);

  return [
    { label: "Alert ID", value: safeString(alert._id || alert.alert_id || "-") },
    { label: "Rule ID", value: getRuleId(alert) || "-" },
    { label: "Rule Description", value: getRuleDescription(alert) },
    { label: "Rule Level", value: getRuleLevel(alert) },
    { label: "Agent ID", value: getAgentId(alert) || "-" },
    { label: "Agent Name", value: getAgentName(alert) },
    { label: "Location", value: getLocation(alert) },
    { label: "Username", value: getUsername(alert) },
    { label: "Process", value: getProcess(alert) },
    { label: "Parent Application", value: getParentApplication(alert) },
    { label: "Command Line", value: getCommandLine(alert) },
    { label: "Source IP", value: rawAlert.data?.srcip || "-" },
    { label: "Destination IP", value: rawAlert.data?.dstip || "-" },
    { label: "MITRE ID", value: mitre.ids.length ? mitre.ids.join(", ") : "-" },
    { label: "MITRE Technique", value: mitre.techniques.length ? mitre.techniques.join(", ") : "-" },
    { label: "MITRE Tactic", value: mitre.tactics.length ? mitre.tactics.join(", ") : "-" },
    { label: "Hashes", value: hashes.length ? hashes.join(", ") : "-" },
    { label: "Network Indicators", value: network.length ? network.join(", ") : "-" },
    { label: "IOC IPs", value: iocs.ips.length ? iocs.ips.join(", ") : "-" },
    { label: "IOC Domains", value: iocs.domains.length ? iocs.domains.join(", ") : "-" },
    { label: "IOC URLs", value: iocs.urls.length ? iocs.urls.join(", ") : "-" },
    { label: "Attack Patterns", value: attackPatterns.length ? attackPatterns.join(", ") : "-" },
  ];
}

function buildAlertTimeline(alert, decision) {
  const createdAt = alert.createdAt || alert.timestamp || new Date();
  const updatedAt = alert.updatedAt || alert.timestamp || createdAt;

  const timeline = [
    {
      title: "Wazuh alert received",
      type: "ALERT_RECEIVED",
      time: createdAt,
      detail: getRuleDescription(alert),
    },
    {
      title: "Alert saved to MongoDB",
      type: "ALERT_SAVED",
      time: createdAt,
      detail: `Stored alert ID ${alert._id}`,
    },
  ];

  if (decision) {
    timeline.push({
      title: "Analyst decision saved",
      type: "ANALYST_DECISION_SAVED",
      time: decision.createdAt || decision.updatedAt || updatedAt,
      detail: `${safeString(decision.analyst, "analyst")} marked this as ${safeString(
        decision.decision,
        "-"
      )}`,
    });
  }

  return timeline;
}

function buildPlaybook(alert, decision) {
  const rawAlert = getRawAlert(alert);
  const verdict = normalizeDecision(decision?.decision || alert.verdict || "needs_investigation");
  const risk = getRiskFromRuleLevel(getRuleLevel(alert));

  let rawText = "";
  try {
    rawText = JSON.stringify(rawAlert).toLowerCase().slice(0, 20000);
  } catch (err) {
    rawText = "";
  }

  const steps = [];

  if (verdict === "false_positive") {
    steps.push(
      {
        step: 1,
        title: "Validate false positive reason",
        description: "Check whether this alert is expected activity for this host/user.",
        status: "pending",
        approval_required: false,
      },
      {
        step: 2,
        title: "Add pattern to tuning backlog",
        description: "Use rule, agent, process, and username to create future suppression logic.",
        status: "pending",
        approval_required: false,
      },
      {
        step: 3,
        title: "Close alert",
        description: "Close only after confirming no suspicious behavior exists in raw evidence.",
        status: "pending",
        approval_required: false,
      }
    );

    return steps;
  }

  if (verdict === "true_positive" || risk >= 80) {
    steps.push(
      {
        step: 1,
        title: "Escalate incident",
        description: "Create or link this alert to an active incident case.",
        status: "approval_required",
        approval_required: true,
      },
      {
        step: 2,
        title: "Collect evidence",
        description: "Preserve event data, process details, and timeline.",
        status: "pending",
        approval_required: false,
      }
    );
  }

  if (rawText.includes("powershell") || rawText.includes("encodedcommand")) {
    steps.push({
      step: steps.length + 1,
      title: "Suspicious PowerShell Review",
      description: "Review command line, parent process, user context, and execution source.",
      status: "pending",
      approval_required: false,
    });
  }

  if (
    rawText.includes("malware") ||
    rawText.includes("trojan") ||
    rawText.includes("ransomware") ||
    rawText.includes("hash")
  ) {
    steps.push({
      step: steps.length + 1,
      title: "Malware Containment",
      description: "Validate hash and prepare affected host isolation.",
      status: "approval_required",
      approval_required: true,
    });
  }

  if (
    rawText.includes("brute") ||
    rawText.includes("authentication failed") ||
    rawText.includes("failed login")
  ) {
    steps.push({
      step: steps.length + 1,
      title: "Brute Force Response",
      description: "Review source IP, failed login pattern, and prepare block action.",
      status: "approval_required",
      approval_required: true,
    });
  }

  if (steps.length === 0) {
    steps.push(
      {
        step: 1,
        title: "Review alert evidence",
        description: "Check event, user, process, location, MITRE data, and history.",
        status: "pending",
        approval_required: false,
      },
      {
        step: 2,
        title: "Search related activity",
        description: "Look for same agent, same user, same process, and same rule.",
        status: "pending",
        approval_required: false,
      },
      {
        step: 3,
        title: "Decide TP / FP / Investigation",
        description: "Save analyst decision after validating the evidence.",
        status: "pending",
        approval_required: false,
      }
    );
  }

  return steps;
}

router.post("/webhook-alert", async (req, res) => {
  try {
    const alert = req.body || {};
    const tenantId = getTenantId(req, alert);

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
      confidence: normalizeConfidence(ai.confidence),
      previous_confidence: 0,
      confidence_adjustment: 0,
      ai_correct: false,
      ai_verdict: aiDecision,
      ai_reasoning: ai.reasoning || "",
      ai_confidence: normalizeConfidence(ai.confidence),
      ai_risk_score: normalizeRisk(ai.risk),
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

    pattern = await updatePatternLearning({
      pattern,
      decision: aiDecision,
      ai: {
        ...ai,
        verdict: aiDecision,
      },
      source: "claude",
    });

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
    console.error("webhook-alert error:", err.message);

    return res.status(500).json({
      error: "Failed to save and triage alert",
      details: err.message,
    });
  }
});

router.get("/webhook-alerts", async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), MAX_LIMIT);
    const tenantId = req.query.tenant_id || req.headers["x-tenant-id"] || null;

    const query = tenantId
      ? {
          $or: [{ tenant_id: tenantId }, { "rawAlert.tenant_id": tenantId }, { tenantId }],
        }
      : {};

    const alerts = await WazuhAlert.find(query)
      .select(
        "tenant_id ruleLevel ruleDescription agentName agentId location timestamp createdAt rawAlert.rule.id rawAlert.rule.level rawAlert.rule.description rawAlert.rule.mitre rawAlert.agent.name rawAlert.agent.id rawAlert.agent.ip rawAlert.location rawAlert.timestamp rawAlert.data.win.eventdata rawAlert.data.audit rawAlert.data.srcuser rawAlert.data.dstuser rawAlert.data.user rawAlert.decoder"
      )
      .sort({ createdAt: -1, _id: -1 })
      .limit(limit)
      .lean();

    return res.json({
      data: alerts.map(compactAlertForResponse),
      alerts: alerts.map(compactAlertForResponse),
      total: alerts.length,
      limit,
    });
  } catch (err) {
    console.error("webhook-alerts error:", err.message);

    return res.status(500).json({
      error: "Failed to fetch alerts",
      details: err.message,
    });
  }
});

router.get("/incidents-lite", async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), MAX_LIMIT);
    const tenantId = req.query.tenant_id || req.headers["x-tenant-id"] || null;

    const query = tenantId
      ? {
          $or: [{ tenant_id: tenantId }, { "rawAlert.tenant_id": tenantId }, { tenantId }],
        }
      : {};

    const alerts = await WazuhAlert.find(query)
      .select(
        "tenant_id ruleLevel ruleDescription agentName agentId location timestamp createdAt rawAlert.rule.id rawAlert.rule.level rawAlert.rule.description rawAlert.agent.name rawAlert.agent.id rawAlert.location rawAlert.timestamp rawAlert.data.win.eventdata rawAlert.data.audit rawAlert.data.srcuser rawAlert.data.dstuser rawAlert.data.user rawAlert.decoder"
      )
      .sort({ createdAt: -1, _id: -1 })
      .limit(limit)
      .lean();

    const incidents = alerts.map((alert) => {
      const ruleLevel = getRuleLevel(alert);
      const risk = getRiskFromRuleLevel(ruleLevel);
      const severity = getSeverityFromRisk(risk);

      return {
        id: String(alert._id),
        alert_id: String(alert._id),
        tenant_id: alert.tenant_id || alert.rawAlert?.tenant_id || DEFAULT_TENANT_ID,
        incidentType: getRuleDescription(alert),
        title: getRuleDescription(alert),
        process: getProcess(alert),
        username: getUsername(alert),
        parentApplication: getParentApplication(alert),
        agentName: getAgentName(alert),
        host: getAgentName(alert),
        severity,
        priority: getPriorityFromSeverity(severity),
        riskScore: risk,
        ruleLevel,
        ruleId: getRuleId(alert) || "-",
        location: getLocation(alert),
        timestamp: getTimestamp(alert),
        createdAt: alert.createdAt,
      };
    });

    return res.json({
      data: incidents,
      incidents,
      total: incidents.length,
      limit,
    });
  } catch (err) {
    console.error("incidents-lite error:", err.message);

    return res.status(500).json({
      error: "Failed to fetch lite incidents",
      details: err.message,
    });
  }
});

router.get("/analyst-queue", async (req, res) => {
  try {
    const limit = Math.min(
      Math.max(parseInt(req.query.limit, 10) || 50, 1),
      MAX_LIMIT
    );

    const tenantId = req.query.tenant_id || req.headers["x-tenant-id"] || null;

    const query = tenantId
      ? {
          $or: [{ tenant_id: tenantId }, { "rawAlert.tenant_id": tenantId }],
        }
      : {};

    const alerts = await WazuhAlert.find(query)
      .select(
        "tenant_id ruleLevel ruleDescription agentName agentId location timestamp createdAt rawAlert.rule.id rawAlert.rule.level rawAlert.rule.description rawAlert.rule.mitre rawAlert.agent.name rawAlert.agent.id rawAlert.agent.ip rawAlert.location rawAlert.timestamp rawAlert.data.srcuser rawAlert.data.dstuser rawAlert.data.user rawAlert.data.audit.uid rawAlert.data.audit.exe rawAlert.data.audit.command rawAlert.data.win.eventdata.targetUserName rawAlert.data.win.eventdata.subjectUserName rawAlert.data.win.eventdata.processName rawAlert.data.win.eventdata.image rawAlert.data.win.eventdata.newProcessName rawAlert.data.win.eventdata.commandLine rawAlert.data.win.eventdata.processCommandLine rawAlert.data.win.eventdata.parentProcessName rawAlert.data.win.eventdata.parentImage"
      )
      .sort({ createdAt: -1, _id: -1 })
      .limit(limit)
      .lean();

    const ids = alerts.map((alert) => String(alert._id));

    const decisions = await AnalystDecision.find({
      alert_id: { $in: ids },
    })
      .select(
        "alert_id tenant_id decision analyst reason status confidence ai_confidence ai_verdict ai_reasoning ai_risk_score recommended_action requires_human_review threat_intel historical_matches fp_rate asset_criticality ai_provider ai_model raw_response createdAt updatedAt"
      )
      .sort({ createdAt: -1, _id: -1 })
      .lean();

    const decisionMap = new Map();

    decisions.forEach((decision) => {
      const key = String(decision.alert_id || "");
      if (key && !decisionMap.has(key)) {
        decisionMap.set(key, decision);
      }
    });

    const patternKeys = alerts.map(getPatternKey).filter(Boolean);

    const patterns = await AlertPattern.find({
      pattern_key: { $in: patternKeys },
    })
      .select(
        "pattern_key tenant_id rule_description rule_id agent agent_id username process occurrences fp_count tp_count investigation_count ai_correct_count ai_wrong_count fp_rate tp_rate ai_accuracy_rate suppression_candidate auto_close_eligible dangerous_pattern ai_quality_risk last_seen last_ai_verdict last_analyst_decision last_confidence last_risk last_reason createdAt updatedAt"
      )
      .lean();

    const patternMap = new Map();

    patterns.forEach((pattern) => {
      if (pattern.pattern_key) {
        patternMap.set(pattern.pattern_key, pattern);
      }
    });

    const data = alerts.map((alert) =>
      buildAnalystQueueItem({
        alert,
        savedDecision: decisionMap.get(String(alert._id)) || null,
        pattern: patternMap.get(getPatternKey(alert)) || null,
      })
    );

    return res.json({
      data,
      alerts: data,
      total: data.length,
      limit,
    });
  } catch (err) {
    console.error("analyst-queue error:", err.message);

    return res.status(500).json({
      error: "Failed analyst queue",
      details: err.message,
    });
  }
});

router.post("/analyst-decision", async (req, res) => {
  try {
    const { alert_id, reason } = req.body || {};
    const decision = normalizeDecision(req.body?.decision);
    const analyst = getAnalyst(req);

    if (!alert_id || !decision) {
      return res.status(400).json({
        error: "alert_id and decision are required",
      });
    }

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
    const status = getStatusFromDecision(decision);

    const savedDecision = await AnalystDecision.create({
      alert_id,
      tenant_id: effectiveTenantId,
      decision,
      analyst,
      reason: safeString(reason || "", "", 1000),
      status,
      confidence: adjustedConfidence,
      previous_confidence: normalizeConfidence(ai.confidence),
      confidence_adjustment: adjustedConfidence - normalizeConfidence(ai.confidence),
      ai_correct: decision === aiVerdict,
      ai_verdict: aiVerdict,
      ai_reasoning: ai.reasoning || "",
      ai_confidence: normalizeConfidence(ai.confidence),
      ai_risk_score: normalizeRisk(ai.risk),
      ai_quality_issue: normalizeConfidence(ai.confidence) > 0.9 && aiVerdict !== decision,
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
          verdict: decision,
        },
        pattern,
        analystDecision: decision,
        analyst,
        analystNotes: reason || "",
      });
    }

    if (decision === "false_positive") {
      await WazuhAlert.findByIdAndUpdate(alert._id, {
        $set: {
          status: "Closed",
          verdict: "false_positive",
          analystDecision: "false_positive",
          analyst,
          analystReason: reason,
          closedAt: new Date(),
          suppressionCandidate: pattern?.suppression_candidate || false,
          autoCloseEligible: pattern?.auto_close_eligible || false,
        },
      });
    }

    return res.json({
      message: "Analyst decision saved",
      decision: compactDecisionForResponse(savedDecision),
      pattern: compactPatternForResponse(pattern),
      incident: compactIncidentForResponse(incident),
    });
  } catch (err) {
    console.error("analyst-decision error:", err.message);

    return res.status(500).json({
      error: "Failed to save analyst decision",
      details: err.message,
    });
  }
});

router.get("/alert-details/:alertId", async (req, res) => {
  try {
    const { alertId } = req.params;

    const alert = await findAlertById(alertId);

    if (!alert) {
      return res.status(404).json({
        error: "Alert not found",
        alertId,
      });
    }

    const decision = await findLatestDecision(alert);
    const rawAlert = getRawAlert(alert);
    const relatedAlerts = await findRelatedAlerts(rawAlert, 20);
    const verdict = normalizeDecision(decision?.decision || alert.verdict || "needs_investigation");
    const confidence = normalizeConfidence(decision?.confidence || alert.confidence || 0);
    const risk = getRiskFromRuleLevel(getRuleLevel(alert));

    return res.json({
      alert_id: String(alert._id),
      id: String(alert._id),
      title: getRuleDescription(alert),
      verdict,
      confidence,
      confidence_percent: Math.round(confidence * 100),
      risk,
      riskScore: risk,
      severity: getSeverityFromRisk(risk),
      priority: getPriorityFromSeverity(getSeverityFromRisk(risk)),
      reasoning: decision?.reason || "-",
      recommended_action: decision?.recommended_action || "-",
      recommendedAction: decision?.recommended_action || "-",
      status: decision
        ? decision.decision === "needs_investigation"
          ? "under_investigation"
          : "reviewed"
        : alert.status || "open",
      agent: getAgentName(alert),
      host: getAgentName(alert),
      process: getProcess(alert),
      username: getUsername(alert),
      user: getUsername(alert),
      timestamp: alert.timestamp || alert.createdAt,
      evidence: buildAlertEvidence(alert),
      timeline: buildAlertTimeline(alert, decision),
      playbook: buildPlaybook(alert, decision),
      analyst_decision: decision ? compactDecisionForResponse(decision) : null,
      related_alerts: relatedAlerts,
      raw: compactAlertForResponse(alert),
    });
  } catch (err) {
    console.error("alert-details error:", err.message);

    return res.status(500).json({
      error: "Failed alert details",
      details: err.message,
    });
  }
});

router.get("/alert-patterns", async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 500, 1), MAX_LIMIT);
    const tenantId = req.query.tenant_id || req.headers["x-tenant-id"] || null;

    const query = tenantId ? { tenant_id: tenantId } : {};

    const patterns = await AlertPattern.find(query)
      .select(
        "pattern_key tenant_id rule_description rule_id agent agent_id username process occurrences fp_count tp_count investigation_count ai_correct_count ai_wrong_count fp_rate tp_rate ai_accuracy_rate suppression_candidate auto_close_eligible dangerous_pattern ai_quality_risk last_seen last_ai_verdict last_analyst_decision last_confidence last_risk last_reason createdAt updatedAt"
      )
      .sort({ last_seen: -1, updatedAt: -1, createdAt: -1 })
      .limit(limit)
      .lean();

    const data = patterns.map(compactPatternForResponse);

    return res.json({
      data,
      patterns: data,
      total: data.length,
      limit,
    });
  } catch (err) {
    console.error("alert-patterns error:", err.message);

    return res.status(500).json({
      error: "Failed to fetch alert patterns",
      details: err.message,
    });
  }
});

router.get("/mitre-lite", async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), MAX_LIMIT);
    const tenantId = req.query.tenant_id || req.headers["x-tenant-id"] || null;

    const query = tenantId
      ? {
          $or: [{ tenant_id: tenantId }, { "rawAlert.tenant_id": tenantId }],
        }
      : {};

    const alerts = await WazuhAlert.find(query)
      .select(
        "tenant_id ruleLevel ruleDescription agentName agentId location timestamp createdAt rawAlert.rule.id rawAlert.rule.level rawAlert.rule.description rawAlert.rule.mitre rawAlert.agent.name rawAlert.agent.id rawAlert.data.win.eventdata.processName rawAlert.data.win.eventdata.image rawAlert.data.srcuser rawAlert.data.dstuser rawAlert.data.user"
      )
      .sort({ createdAt: -1, _id: -1 })
      .limit(limit)
      .lean();

    const data = alerts.map((alert) => {
      const raw = getRawAlert(alert);
      const mitre = extractMitre(raw);
      const risk = getRiskFromRuleLevel(getRuleLevel(alert));
      const confidence = 0;

      return {
        id: String(alert._id),
        alert_id: String(alert._id),
        title: getRuleDescription(alert),
        host: getAgentName(alert),
        agent: getAgentName(alert),
        process: getProcess(alert),
        user: getUsername(alert),
        risk,
        confidence,
        verdict: "needs_investigation",
        tactics: mitre.tactics,
        techniques: mitre.techniques,
        ids: mitre.ids,
        timestamp: getTimestamp(alert),
      };
    });

    return res.json({
      data,
      total: data.length,
      limit,
    });
  } catch (err) {
    console.error("mitre-lite error:", err.message);

    return res.status(500).json({
      error: "Failed MITRE lite",
      details: err.message,
    });
  }
});

router.get("/summary", async (req, res) => {
  try {
    const [alerts, incidents, patterns] = await Promise.all([
      WazuhAlert.countDocuments({}),
      Incident.countDocuments({}),
      AlertPattern.countDocuments({}),
    ]);

    const openIncidents = await Incident.countDocuments({
      status: { $in: ["Open", "Under Investigation", "Investigating"] },
    });

    return res.json({
      alerts,
      incidents,
      openIncidents,
      patterns,
      status: "live",
      manager: {
        name: "Wazuh Manager",
        version: "Unknown",
      },
    });
  } catch (err) {
    console.error("summary error:", err.message);

    return res.status(500).json({
      error: "Failed summary",
      details: err.message,
    });
  }
});

router.get("/agent-incidents", async (req, res) => {
  try {
    return res.json({
      data: [],
      incidents: [],
      total: 0,
    });
  } catch (err) {
    return res.status(500).json({
      error: "Failed agent incidents",
      details: err.message,
    });
  }
});

router.get("/agents", async (req, res) => {
  try {
    return res.json({
      data: [],
      agents: [],
      total: 0,
    });
  } catch (err) {
    return res.status(500).json({
      error: "Failed agents",
      details: err.message,
    });
  }
});

router.get("/vulnerabilities", async (req, res) => {
  try {
    return res.json({
      data: [],
      vulnerabilities: [],
      total: 0,
    });
  } catch (err) {
    return res.status(500).json({
      error: "Failed vulnerabilities",
      details: err.message,
    });
  }
});

router.get("/claude-cache-stats", async (req, res) => {
  try {
    return res.json({
      ok: true,
      data: getClaudeCacheStats(),
    });
  } catch (err) {
    console.error("claude-cache-stats:", err);

    return res.status(500).json({
      ok: false,
      error: err.message,
    });
  }
});

module.exports = router;