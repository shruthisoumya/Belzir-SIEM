const Incident = require("../models/Incident");

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function uniqueArray(values = []) {
  return [...new Set(values.filter(Boolean))];
}

function normalizeVerdict(verdict = "") {
  if (verdict === "tp") return "true_positive";
  if (verdict === "fp") return "false_positive";
  if (verdict === "investigate") return "needs_investigation";
  if (verdict === "needs_review") return "needs_investigation";
  return verdict || "needs_review";
}

function getLatestEvidence(incident = {}) {
  const evidence = safeArray(incident.evidence);
  return evidence.length ? evidence[evidence.length - 1] : {};
}

function buildProcessSummary(incident = {}) {
  const processes = uniqueArray([
    ...safeArray(incident.processes),
    ...safeArray(incident.evidence).map((item) => item.process),
  ]);

  const processTree = safeArray(incident.evidence)
    .filter((item) => item.process || item.parent_process || item.command_line)
    .map((item) => ({
      alert_id: item.alert_id || "",
      process: item.process || "-",
      parent_process: item.parent_process || "-",
      command_line: item.command_line || "-",
      username: item.username || "-",
    }));

  return {
    processes,
    processTree,
    suspiciousProcessCount: processes.filter((item) =>
      String(item).toLowerCase().includes("powershell") ||
      String(item).toLowerCase().includes("cmd") ||
      String(item).toLowerCase().includes("wmic") ||
      String(item).toLowerCase().includes("psexec")
    ).length,
  };
}

function buildNetworkSummary(incident = {}) {
  const evidence = safeArray(incident.evidence);

  const sourceIPs = uniqueArray([
    ...safeArray(incident.sourceIPs),
    ...evidence.map((item) => item.source_ip),
  ]).filter((item) => item !== "-");

  const destinationIPs = uniqueArray([
    ...safeArray(incident.destinationIPs),
    ...evidence.map((item) => item.destination_ip),
  ]).filter((item) => item !== "-");

  const networkIndicators = uniqueArray([
    ...safeArray(incident.networkConnections),
    ...evidence.flatMap((item) => safeArray(item.network_indicators)),
  ]);

  return {
    sourceIPs,
    destinationIPs,
    networkIndicators,
    hasNetworkActivity:
      sourceIPs.length > 0 ||
      destinationIPs.length > 0 ||
      networkIndicators.length > 0,
  };
}

function buildUserSummary(incident = {}) {
  const evidence = safeArray(incident.evidence);

  const users = uniqueArray([
    ...safeArray(incident.users),
    ...evidence.map((item) => item.username),
  ]).filter((item) => item && item !== "-");

  return {
    users,
    userCount: users.length,
    hasUnknownUser:
      users.length === 0 ||
      evidence.some((item) => !item.username || item.username === "-"),
  };
}

function buildThreatSummary(incident = {}) {
  const evidence = safeArray(incident.evidence);

  const iocs = uniqueArray([
    ...safeArray(incident.iocs),
    ...safeArray(incident.indicators),
    ...safeArray(incident.hashes),
    ...safeArray(incident.urls),
    ...safeArray(incident.domains),
    ...evidence.flatMap((item) => safeArray(item.hashes)),
    ...evidence.flatMap((item) => safeArray(item.network_indicators)),
  ]);

  const attackPatterns = uniqueArray([
    ...safeArray(incident.riskFactors),
    ...safeArray(incident.tags),
    ...evidence.flatMap((item) => safeArray(item.attack_patterns)),
  ]);

  const mitreTechniques = uniqueArray([
    ...safeArray(incident.mitreTechniques),
    ...evidence.flatMap((item) => safeArray(item.mitre_techniques)),
  ]);

  return {
    iocs,
    attackPatterns,
    mitreTechniques,
    threatIntel: incident.threatIntel || "none",
    hasThreatIntel:
      incident.threatIntel &&
      String(incident.threatIntel).toLowerCase() !== "none" &&
      String(incident.threatIntel).toLowerCase() !== "no malicious ioc found",
  };
}

function buildBehaviorSummary(incident = {}) {
  const relatedAlerts = safeArray(incident.relatedAlerts);
  const evidence = safeArray(incident.evidence);
  const latestEvidence = getLatestEvidence(incident);

  const firstSeen = incident.firstSeen || incident.createdAt || null;
  const lastSeen = incident.lastSeen || incident.updatedAt || null;

  return {
    firstSeen,
    lastSeen,
    relatedAlertCount: relatedAlerts.length,
    evidenceCount: evidence.length,
    repeatedBehavior: relatedAlerts.length >= 5 || evidence.length >= 5,
    latestRule: latestEvidence.rule_description || incident.title || "",
    latestProcess: latestEvidence.process || "",
    latestCommandLine: latestEvidence.command_line || "",
  };
}

function buildInvestigationFindings(incident = {}) {
  const findings = [];
  const processSummary = buildProcessSummary(incident);
  const networkSummary = buildNetworkSummary(incident);
  const userSummary = buildUserSummary(incident);
  const threatSummary = buildThreatSummary(incident);
  const behaviorSummary = buildBehaviorSummary(incident);

  if (behaviorSummary.repeatedBehavior) {
    findings.push({
      type: "REPEATED_BEHAVIOR",
      severity: "Medium",
      message: `Repeated behavior detected with ${behaviorSummary.relatedAlertCount} related alerts and ${behaviorSummary.evidenceCount} evidence records.`,
    });
  }

  if (processSummary.suspiciousProcessCount > 0) {
    findings.push({
      type: "SUSPICIOUS_PROCESS",
      severity: "High",
      message: "Suspicious process activity detected in investigation evidence.",
    });
  }

  if (userSummary.hasUnknownUser) {
    findings.push({
      type: "UNKNOWN_USER_CONTEXT",
      severity: "Medium",
      message: "User context is missing or unknown and should be validated.",
    });
  }

  if (networkSummary.hasNetworkActivity) {
    findings.push({
      type: "NETWORK_ACTIVITY",
      severity: "Medium",
      message: "Network indicators are present and should be reviewed.",
    });
  }

  if (threatSummary.hasThreatIntel) {
    findings.push({
      type: "THREAT_INTEL_CONTEXT",
      severity: "High",
      message: "Threat intelligence context is present in the incident.",
    });
  }

  return findings;
}

function buildInvestigationChecklist(incident = {}) {
  const latestEvidence = getLatestEvidence(incident);
  const checklist = [
    {
      item: "Validate whether the activity is expected business/admin activity",
      status: "pending",
    },
    {
      item: "Confirm affected host and asset owner",
      status: "pending",
    },
    {
      item: "Identify user account and login context",
      status: "pending",
    },
    {
      item: "Review process parent/child relationship",
      status: "pending",
    },
    {
      item: "Review command line and decode suspicious payload if applicable",
      status: "pending",
    },
    {
      item: "Check for repeated alerts or campaign behavior",
      status: "pending",
    },
    {
      item: "Review threat intelligence and IOC context",
      status: "pending",
    },
    {
      item: "Decide final analyst verdict: TP, FP, or continued investigation",
      status: "pending",
    },
  ];

  if (
    latestEvidence.command_line &&
    String(latestEvidence.command_line).toLowerCase().includes("encodedcommand")
  ) {
    checklist.unshift({
      item: "Decode PowerShell EncodedCommand payload",
      status: "priority",
    });
  }

  return checklist;
}

function buildClaudeInvestigationContext(incident = {}) {
  return {
    incidentKey: incident.incidentKey,
    title: incident.title,
    severity: incident.severity,
    priority: incident.priority,
    verdict: normalizeVerdict(incident.verdict),
    riskScore: incident.riskScore,
    aiConfidence: incident.aiConfidence,
    host: incident.host,
    assetCriticality: incident.assetCriticality,
    status: incident.status,
    processSummary: buildProcessSummary(incident),
    networkSummary: buildNetworkSummary(incident),
    userSummary: buildUserSummary(incident),
    threatSummary: buildThreatSummary(incident),
    behaviorSummary: buildBehaviorSummary(incident),
    findings: buildInvestigationFindings(incident),
    recentEvidence: safeArray(incident.evidence).slice(-5),
    timeline: safeArray(incident.timeline).slice(-10),
  };
}

async function enrichInvestigationIncident(incidentId, actor = "investigation-engine") {
  const incident = await Incident.findById(incidentId);

  if (!incident) {
    return null;
  }

  const investigation = {
    enrichedAt: new Date().toISOString(),
    processSummary: buildProcessSummary(incident),
    networkSummary: buildNetworkSummary(incident),
    userSummary: buildUserSummary(incident),
    threatSummary: buildThreatSummary(incident),
    behaviorSummary: buildBehaviorSummary(incident),
    findings: buildInvestigationFindings(incident),
    checklist: buildInvestigationChecklist(incident),
    claudeContext: buildClaudeInvestigationContext(incident),
  };

  incident.enrichment = {
    ...(incident.enrichment || {}),
    investigation,
  };

  incident.investigationStatus = "enriched";

  if (!Array.isArray(incident.timeline)) {
    incident.timeline = [];
  }

  incident.timeline.push({
    time: new Date().toISOString(),
    type: "INVESTIGATION_ENRICHED",
    actor,
    message:
      "Investigation enrichment completed with process, user, network, threat, behavior, checklist, and Claude-ready context.",
  });

  await incident.save();

  return incident;
}

module.exports = {
  enrichInvestigationIncident,
  buildProcessSummary,
  buildNetworkSummary,
  buildUserSummary,
  buildThreatSummary,
  buildBehaviorSummary,
  buildInvestigationFindings,
  buildInvestigationChecklist,
  buildClaudeInvestigationContext,
};