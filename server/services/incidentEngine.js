const Incident = require("../models/Incident");

const {
  findCorrelatedIncidents,
  buildCampaignMetadata,
} = require("./correlationEngine");

function safeString(value, fallback = "") {
  if (value === null || value === undefined) return fallback;
  return String(value);
}

function normalizeVerdict(verdict = "") {
  if (verdict === "tp") return "true_positive";
  if (verdict === "fp") return "false_positive";
  if (verdict === "investigate") return "needs_investigation";
  if (verdict === "needs_review") return "needs_investigation";
  return verdict || "needs_review";
}

function getThreatIntelValue(ai = {}, raw = {}) {
  return ai.threat_intel || ai.threatIntel || raw.threat_intel || raw.threatIntel || "none";
}

function hasThreatIntelHit(threatIntel) {
  if (!threatIntel) return false;

  if (typeof threatIntel === "string") {
    const value = threatIntel.toLowerCase();
    return (
      value !== "none" &&
      value !== "no malicious ioc found" &&
      value !== "no hit" &&
      value !== "no hits" &&
      value !== "clean" &&
      value !== "-"
    );
  }

  if (Array.isArray(threatIntel)) return threatIntel.length > 0;

  if (typeof threatIntel === "object") {
    return Object.values(threatIntel).some((value) => {
      if (Array.isArray(value)) return value.length > 0;
      if (typeof value === "boolean") return value === true;
      if (typeof value === "number") return value > 0;
      if (typeof value === "string") return hasThreatIntelHit(value);
      return false;
    });
  }

  return false;
}

function getRiskScore(alert = {}, ai = {}) {
  const raw = alert.rawAlert || {};
  const value =
    ai.risk ??
    ai.riskScore ??
    ai.risk_score ??
    alert.risk ??
    alert.riskScore ??
    alert.ruleLevel ??
    raw.rule?.level ??
    0;

  const numeric = Number(value);
  return Number.isNaN(numeric) ? 0 : numeric;
}

function getConfidence(ai = {}) {
  const value = ai.confidence ?? ai.aiConfidence ?? 0;
  const numeric = Number(value);
  return Number.isNaN(numeric) ? 0 : numeric;
}

function getHistoricalMatches(ai = {}, pattern = null) {
  const value =
    ai.historical_matches ?? ai.historicalMatches ?? pattern?.occurrences ?? 0;

  const numeric = Number(value);
  return Number.isNaN(numeric) ? 0 : numeric;
}

function getFpRate(ai = {}, pattern = null) {
  const value =
    pattern?.fp_rate ?? pattern?.fpRate ?? ai.fp_rate ?? ai.fpRate ?? 0;

  const numeric = Number(value);
  return Number.isNaN(numeric) ? 0 : numeric;
}

function getAssetCriticality(ai = {}, alert = {}) {
  const raw = alert.rawAlert || {};

  return (
    ai.asset_criticality ||
    ai.assetCriticality ||
    raw.asset_criticality ||
    raw.assetCriticality ||
    raw.agent?.asset_criticality ||
    raw.agent?.assetCriticality ||
    "UNKNOWN"
  );
}

function extractRuleDescription(alert = {}) {
  const raw = alert.rawAlert || {};

  return (
    alert.ruleDescription ||
    alert.rule_description ||
    raw.rule?.description ||
    raw.rule?.id ||
    "Wazuh Alert"
  );
}

function extractRuleId(alert = {}) {
  const raw = alert.rawAlert || {};
  return alert.ruleId || alert.rule_id || raw.rule?.id || "-";
}

function extractRuleLevel(alert = {}) {
  const raw = alert.rawAlert || {};
  return alert.ruleLevel || alert.rule_level || raw.rule?.level || 0;
}

function extractAgentName(alert = {}) {
  const raw = alert.rawAlert || {};
  return alert.agentName || alert.agent || raw.agent?.name || "unknown-agent";
}

function extractAgentId(alert = {}) {
  const raw = alert.rawAlert || {};
  return alert.agentId || raw.agent?.id || "";
}

function extractAgentIp(alert = {}) {
  const raw = alert.rawAlert || {};

  return (
    raw.agent?.ip ||
    raw.data?.srcip ||
    raw.data?.dstip ||
    raw.data?.win?.eventdata?.ipAddress ||
    raw.data?.win?.eventdata?.sourceIp ||
    ""
  );
}

function extractOs(alert = {}) {
  const raw = alert.rawAlert || {};
  return raw.agent?.os?.name || raw.agent?.os || "";
}

function extractUsername(alert = {}) {
  const raw = alert.rawAlert || {};

  return (
    raw.data?.win?.eventdata?.targetUserName ||
    raw.data?.win?.eventdata?.subjectUserName ||
    raw.data?.win?.eventdata?.user ||
    raw.data?.audit?.uid ||
    raw.data?.srcuser ||
    raw.data?.dstuser ||
    raw.user ||
    "-"
  );
}

function extractProcess(alert = {}) {
  const raw = alert.rawAlert || {};

  return (
    raw.data?.win?.eventdata?.processName ||
    raw.data?.win?.eventdata?.image ||
    raw.data?.win?.eventdata?.newProcessName ||
    raw.data?.win?.eventdata?.commandLine ||
    raw.data?.audit?.exe ||
    raw.process?.name ||
    raw.process ||
    "-"
  );
}

function extractCommandLine(alert = {}) {
  const raw = alert.rawAlert || {};

  return (
    raw.data?.win?.eventdata?.commandLine ||
    raw.data?.win?.eventdata?.processCommandLine ||
    raw.process?.command_line ||
    raw.command_line ||
    "-"
  );
}

function extractParentProcess(alert = {}) {
  const raw = alert.rawAlert || {};

  return (
    raw.data?.win?.eventdata?.parentProcessName ||
    raw.data?.win?.eventdata?.parentImage ||
    raw.process?.parent?.name ||
    "-"
  );
}

function extractHashes(alert = {}) {
  const raw = alert.rawAlert || {};
  const hashes = [];

  const hashSources = [
    raw.data?.win?.eventdata?.hashes,
    raw.data?.win?.eventdata?.hash,
    raw.data?.hash,
    raw.syscheck?.sha256_after,
    raw.syscheck?.md5_after,
  ];

  hashSources.forEach((item) => {
    if (!item) return;

    if (typeof item === "string") {
      item
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean)
        .forEach((value) => hashes.push(value));
    }

    if (Array.isArray(item)) {
      item.filter(Boolean).forEach((value) => hashes.push(value));
    }
  });

  return [...new Set(hashes)];
}

function extractNetworkIndicators(alert = {}) {
  const raw = alert.rawAlert || {};
  const indicators = [];

  const values = [
    raw.data?.srcip,
    raw.data?.dstip,
    raw.data?.srcport,
    raw.data?.dstport,
    raw.data?.protocol,
    raw.data?.win?.eventdata?.ipAddress,
    raw.data?.win?.eventdata?.sourceIp,
    raw.data?.win?.eventdata?.destinationIp,
    raw.data?.win?.eventdata?.destinationPort,
    raw.data?.win?.eventdata?.sourcePort,
  ];

  values.filter(Boolean).forEach((value) => indicators.push(String(value)));

  return [...new Set(indicators)];
}

function extractMitreTechniques(alert = {}) {
  const raw = alert.rawAlert || {};
  const mitre = raw.rule?.mitre || raw.mitre || {};

  const techniques = [
    ...(Array.isArray(mitre.id) ? mitre.id : mitre.id ? [mitre.id] : []),
    ...(Array.isArray(mitre.technique)
      ? mitre.technique
      : mitre.technique
      ? [mitre.technique]
      : []),
    ...(Array.isArray(mitre.tactic) ? mitre.tactic : mitre.tactic ? [mitre.tactic] : []),
  ];

  return [...new Set(techniques.filter(Boolean))];
}

function extractIoCs(alert = {}) {
  const raw = alert.rawAlert || {};
  const text = JSON.stringify(raw);

  const ips = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  const domains = text.match(/\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g) || [];
  const urls = text.match(/https?:\/\/[^\s"]+/g) || [];

  return {
    ips: [...new Set(ips)],
    domains: [...new Set(domains)],
    urls: [...new Set(urls)],
  };
}

function hasKeyword(alert = {}, keywords = []) {
  const raw = alert.rawAlert || {};
  const text = JSON.stringify(raw).toLowerCase();

  return keywords.some((keyword) => text.includes(keyword.toLowerCase()));
}

function detectAttackPatterns(alert = {}) {
  const detections = [];

  if (
    hasKeyword(alert, [
      "authentication failed",
      "failed password",
      "brute force",
      "invalid user",
    ])
  ) {
    detections.push("BRUTE_FORCE");
  }

  if (
    hasKeyword(alert, ["powershell", "encodedcommand", "iex", "invoke-expression"])
  ) {
    detections.push("POWERSHELL_ATTACK");
  }

  if (hasKeyword(alert, ["mimikatz", "credential dumping", "lsass"])) {
    detections.push("CREDENTIAL_ACCESS");
  }

  if (hasKeyword(alert, ["lateral movement", "psexec", "wmic", "remote execution"])) {
    detections.push("LATERAL_MOVEMENT");
  }

  if (hasKeyword(alert, ["c2", "command and control", "beacon", "reverse shell"])) {
    detections.push("COMMAND_AND_CONTROL");
  }

  return [...new Set(detections)];
}

function buildInvestigationEnrichment(alert = {}) {
  const raw = alert.rawAlert || {};
  const username = extractUsername(alert);
  const process = extractProcess(alert);
  const parentApplication = extractParentProcess(alert);
  const commandLine = extractCommandLine(alert);
  const iocs = extractIoCs(alert);

  const sourceIP =
    raw.data?.srcip ||
    raw.data?.win?.eventdata?.sourceIp ||
    raw.data?.win?.eventdata?.ipAddress ||
    "-";

  const destinationIP =
    raw.data?.dstip || raw.data?.win?.eventdata?.destinationIp || "-";

  const destinationPort =
    raw.data?.dstport || raw.data?.win?.eventdata?.destinationPort || "-";

  const sourcePort =
    raw.data?.srcport || raw.data?.win?.eventdata?.sourcePort || "-";

  const protocol = raw.data?.protocol || raw.data?.win?.eventdata?.protocol || "-";

  const eventHour = new Date(raw.timestamp || alert.timestamp || alert.createdAt || Date.now()).getHours();

  return {
    dnsHistory: {
      queries: [
        raw.data?.dns?.query,
        raw.data?.dns?.hostname,
        raw.data?.hostname,
        ...iocs.domains,
        ...iocs.urls,
      ].filter(Boolean),
      source: "wazuh_raw_alert",
      status: iocs.domains.length || iocs.urls.length ? "observed" : "not_observed",
    },

    processTree: {
      parentApplication,
      process,
      commandLine,
      lineage: [parentApplication, process].filter((item) => item && item !== "-"),
      suspicious:
        String(process).toLowerCase().includes("powershell") ||
        String(commandLine).toLowerCase().includes("encodedcommand") ||
        String(commandLine).toLowerCase().includes("-enc"),
    },

    networkActivity: {
      sourceIP,
      sourcePort,
      destinationIP,
      destinationPort,
      protocol,
      connections: extractNetworkIndicators(alert),
      externalConnection:
        destinationIP !== "-" &&
        !String(destinationIP).startsWith("10.") &&
        !String(destinationIP).startsWith("192.168.") &&
        !String(destinationIP).startsWith("172."),
    },

    userAnomaly: {
      username,
      privileged:
        String(username).toLowerCase().includes("admin") ||
        String(username).toLowerCase().includes("root") ||
        String(username).toLowerCase().includes("super"),
      suspiciousHours: eventHour < 6 || eventHour > 22,
      userSeenInAlert: username !== "-",
      requiresReview:
        username !== "-" &&
        (eventHour < 6 ||
          eventHour > 22 ||
          String(username).toLowerCase().includes("admin") ||
          String(username).toLowerCase().includes("root")),
    },
  };
}

function getSeverity(riskScore = 0, incidentType = "investigation", alert = {}) {
  const attackPatterns = detectAttackPatterns(alert);

  if (
    incidentType === "security" &&
    (attackPatterns.includes("CREDENTIAL_ACCESS") ||
      attackPatterns.includes("LATERAL_MOVEMENT") ||
      attackPatterns.includes("COMMAND_AND_CONTROL"))
  ) {
    return "Critical";
  }

  if (incidentType === "security") {
    if (riskScore >= 85) return "Critical";
    if (riskScore >= 70) return "High";
    return "Medium";
  }

  if (incidentType === "investigation") return "Medium";
  if (incidentType === "ai_quality") return "Medium";
  if (incidentType === "operational") return "Medium";

  if (incidentType === "detection_tuning") {
    return riskScore >= 60 ? "Medium" : "Low";
  }

  if (riskScore >= 80) return "Critical";
  if (riskScore >= 60) return "High";
  if (riskScore >= 30) return "Medium";
  return "Low";
}

function getPriority(severity = "Low") {
  if (severity === "Critical") return "P1";
  if (severity === "High") return "P2";
  if (severity === "Medium") return "P3";
  return "P4";
}

function getIncidentType({ alert, ai, pattern, analystDecision = null }) {
  const verdict = normalizeVerdict(analystDecision || ai?.verdict);
  const riskScore = getRiskScore(alert, ai);
  const confidence = getConfidence(ai);
  const fpRate = getFpRate(ai, pattern);
  const occurrences = getHistoricalMatches(ai, pattern);
  const threatIntel = getThreatIntelValue(ai, alert?.rawAlert || {});
  const assetCriticality = getAssetCriticality(ai, alert);
  const threatIntelHit = hasThreatIntelHit(threatIntel);
  const attackPatterns = detectAttackPatterns(alert);

  const highRiskSecuritySignal =
    attackPatterns.length > 0 || extractMitreTechniques(alert).length > 0;

  if (verdict === "true_positive") return "security";

  if (verdict === "needs_review" || verdict === "needs_investigation") {
    return "investigation";
  }

  if (verdict === "false_positive" && fpRate > 0.9 && occurrences > 50) {
    return "detection_tuning";
  }

  if (
    verdict === "false_positive" &&
    confidence > 0.9 &&
    assetCriticality !== "HIGH" &&
    !threatIntelHit &&
    occurrences > 10
  ) {
    return "detection_tuning";
  }

  if (
    confidence > 0.9 &&
    analystDecision &&
    normalizeVerdict(ai?.verdict) !== verdict
  ) {
    return "ai_quality";
  }

  if (riskScore > 70 || threatIntelHit || assetCriticality === "HIGH" || highRiskSecuritySignal) {
    return "investigation";
  }

  return null;
}

function getIncidentClassification(incidentType) {
  if (incidentType === "security") return "Security Incident";
  if (incidentType === "investigation") return "Investigation Incident";
  if (incidentType === "detection_tuning") return "Detection Tuning Incident";
  if (incidentType === "operational") return "Operational Incident";
  if (incidentType === "ai_quality") return "AI Quality Incident";
  return "Incident";
}

function buildIncidentKey(alert, incidentType) {
  const rule = extractRuleDescription(alert);
  const agent = extractAgentName(alert);

  return `${incidentType}-${agent}-${rule}`
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 180);
}

function buildTitle(alert, incidentType) {
  return `${getIncidentClassification(incidentType)} - ${extractRuleDescription(alert)}`;
}

function buildAttackChain(alert = {}) {
  const chain = [];
  const patterns = detectAttackPatterns(alert);

  if (patterns.includes("BRUTE_FORCE")) chain.push("Initial Access");
  if (patterns.includes("POWERSHELL_ATTACK")) chain.push("Execution");
  if (patterns.includes("CREDENTIAL_ACCESS")) chain.push("Credential Access");
  if (patterns.includes("LATERAL_MOVEMENT")) chain.push("Lateral Movement");
  if (patterns.includes("COMMAND_AND_CONTROL")) chain.push("Command and Control");

  return [...new Set(chain)];
}

function buildEvidence(alert, ai, pattern, campaignMetadata = null) {
  const raw = alert.rawAlert || {};
  const process = extractProcess(alert);
  const username = extractUsername(alert);
  const commandLine = extractCommandLine(alert);
  const parentProcess = extractParentProcess(alert);
  const hashes = extractHashes(alert);
  const networkIndicators = extractNetworkIndicators(alert);
  const mitreTechniques = extractMitreTechniques(alert);
  const attackPatterns = detectAttackPatterns(alert);
  const iocs = extractIoCs(alert);
  const investigation = buildInvestigationEnrichment(alert);

  return {
    alert_id: String(alert._id),
    rule_id: extractRuleId(alert),
    rule_level: extractRuleLevel(alert),
    rule_description: extractRuleDescription(alert),
    agent: extractAgentName(alert),
    agent_id: extractAgentId(alert),
    location: alert.location || raw.location || "-",
    process,
    parent_process: parentProcess,
    parent_application: parentProcess,
    command_line: commandLine,
    username,
    source_ip: raw.data?.srcip || raw.data?.win?.eventdata?.sourceIp || "-",
    destination_ip: raw.data?.dstip || raw.data?.win?.eventdata?.destinationIp || "-",
    hashes,
    network_indicators: networkIndicators,
    mitre_techniques: mitreTechniques,
    attack_patterns: attackPatterns,
    iocs,
    dns_history: investigation.dnsHistory,
    process_tree: investigation.processTree,
    network_activity: investigation.networkActivity,
    user_anomaly: investigation.userAnomaly,
    attack_chain: buildAttackChain(alert),
    campaign: campaignMetadata || {},
    risk: getRiskScore(alert, ai),
    confidence: getConfidence(ai),
    verdict: normalizeVerdict(ai?.verdict),
    reasoning: ai?.reasoning || "-",
    recommended_action: ai?.recommended_action || ai?.recommendedAction || "-",
    historical_matches: getHistoricalMatches(ai, pattern),
    fp_rate: getFpRate(ai, pattern),
    threat_intel: getThreatIntelValue(ai, raw),
    pattern_key: pattern?.pattern_key || pattern?.patternKey || "-",
    raw_alert: raw,
  };
}

function buildPlaybooks(alert, incidentType, ai = {}, campaignMetadata = {}) {
  const playbooks = [];
  const attackPatterns = detectAttackPatterns(alert);

  if (attackPatterns.includes("BRUTE_FORCE")) {
    playbooks.push({
      title: "Brute Force Containment",
      action: "Block attacking IP and review authentication logs",
      status: "approval_required",
      approval_required: true,
    });
  }

  if (attackPatterns.includes("POWERSHELL_ATTACK")) {
    playbooks.push({
      title: "PowerShell Threat Investigation",
      action: "Collect encoded command, process lineage and isolate host if malicious",
      status: "approval_required",
      approval_required: true,
    });
  }

  if (attackPatterns.includes("LATERAL_MOVEMENT")) {
    playbooks.push({
      title: "Lateral Movement Containment",
      action: "Review remote execution paths, isolate hosts and reset credentials",
      status: "approval_required",
      approval_required: true,
    });
  }

  if (attackPatterns.includes("CREDENTIAL_ACCESS")) {
    playbooks.push({
      title: "Credential Theft Response",
      action: "Investigate credential dumping activity and rotate impacted credentials",
      status: "approval_required",
      approval_required: true,
    });
  }

  if (attackPatterns.includes("COMMAND_AND_CONTROL")) {
    playbooks.push({
      title: "C2 Network Blocking",
      action: "Block suspicious outbound communication and investigate persistence",
      status: "approval_required",
      approval_required: true,
    });
  }

  if (campaignMetadata?.campaignDetected) {
    playbooks.push({
      title: "Campaign Investigation",
      action:
        campaignMetadata.recommendedAction ||
        "Review correlated incidents and validate coordinated attack progression",
      status: "approval_required",
      approval_required: true,
    });
  }

  if (incidentType === "investigation") {
    playbooks.push({
      title: "Investigation Enrichment",
      action:
        "Collect DNS history, process tree, network activity and user anomaly context",
      status: "pending",
      approval_required: false,
    });
  }

  if (playbooks.length === 0 && ai?.recommended_action) {
    playbooks.push({
      title: "Recommended Analyst Action",
      action: ai.recommended_action,
      status: "pending",
      approval_required: incidentType === "security",
    });
  }

  return playbooks;
}

function buildTimelineEvent({
  alert,
  ai,
  analystDecision,
  analyst,
  incidentType,
  riskScore,
  campaignMetadata = {},
}) {
  const verdict = normalizeVerdict(analystDecision || ai?.verdict);

  return {
    time: new Date().toISOString(),
    type: campaignMetadata.campaignDetected
      ? "CAMPAIGN_CORRELATION"
      : analystDecision === "true_positive"
      ? "TP_CONFIRMED"
      : analystDecision === "false_positive"
      ? "FP_CONFIRMED"
      : analystDecision === "needs_investigation"
      ? "INVESTIGATION_REQUESTED"
      : incidentType === "detection_tuning"
      ? "DETECTION_TUNING_CREATED"
      : incidentType === "ai_quality"
      ? "AI_QUALITY_CREATED"
      : "AI_TRIAGE",
    actor: analyst,
    message: campaignMetadata.campaignDetected
      ? `Correlated campaign detected with ${campaignMetadata.correlatedIncidentCount} related incidents.`
      : analystDecision === "true_positive"
      ? "Analyst confirmed true positive. Security incident created or updated."
      : analystDecision === "false_positive"
      ? "Analyst confirmed false positive. Pattern reviewed for tuning."
      : analystDecision === "needs_investigation"
      ? "Analyst requested further investigation. Investigation incident created or updated."
      : incidentType === "detection_tuning"
      ? "High false-positive pattern detected. Detection tuning incident created or updated."
      : incidentType === "ai_quality"
      ? "AI disagreement detected. AI quality incident created or updated."
      : "AI triage created or updated incident.",
    alert_id: String(alert._id),
    verdict,
    confidence: getConfidence(ai),
    risk: riskScore,
    campaign: campaignMetadata,
  };
}

function getStatus(incidentType, analystDecision = null) {
  if (analystDecision === "needs_investigation") return "Under Investigation";
  if (incidentType === "investigation") return "Under Investigation";
  if (incidentType === "security") return "Open";
  if (incidentType === "detection_tuning") return "Open";
  if (incidentType === "operational") return "Open";
  if (incidentType === "ai_quality") return "Open";
  return "Open";
}

function mergeUnique(existing = [], incoming = []) {
  const current = Array.isArray(existing) ? existing : [];
  const next = Array.isArray(incoming) ? incoming : [];
  return [...new Set([...current, ...next].filter(Boolean))];
}

async function createOrUpdateIncident({
  alert,
  ai,
  pattern = null,
  analystDecision = null,
  analyst = "system",
  analystNotes = "",
}) {
  const normalizedAnalystDecision = analystDecision
    ? normalizeVerdict(analystDecision)
    : null;

  const incidentType = getIncidentType({
    alert,
    ai,
    pattern,
    analystDecision: normalizedAnalystDecision,
  });

  if (!incidentType) return null;

  const raw = alert.rawAlert || {};
  const campaignMetadata = await buildCampaignMetadata(alert);
  const relatedIncidents = await findCorrelatedIncidents(alert);
  const investigationEnrichment = buildInvestigationEnrichment(alert);

  const baseRiskScore = getRiskScore(alert, ai);
  const campaignRiskBoost = campaignMetadata.campaignDetected ? 10 : 0;
  const riskScore = Math.min(100, baseRiskScore + campaignRiskBoost);

  let severity = getSeverity(riskScore, incidentType, alert);

  if (campaignMetadata.campaignDetected && campaignMetadata.correlatedIncidentCount >= 3) {
    severity = "Critical";
  }

  const priority = getPriority(severity);
  const incidentKey = buildIncidentKey(alert, incidentType);
  const classification = getIncidentClassification(incidentType);
  const title = buildTitle(alert, incidentType);
  const evidence = buildEvidence(alert, ai, pattern, campaignMetadata);
  const playbooks = buildPlaybooks(alert, incidentType, ai, campaignMetadata);

  const timelineEvent = buildTimelineEvent({
    alert,
    ai,
    analystDecision: normalizedAnalystDecision,
    analyst,
    incidentType,
    riskScore,
    campaignMetadata,
  });

  const note =
    analystNotes && analystNotes.trim()
      ? {
          time: new Date().toISOString(),
          analyst,
          note: analystNotes,
          alert_id: String(alert._id),
        }
      : null;

  const status = getStatus(incidentType, normalizedAnalystDecision);
  const threatIntel = getThreatIntelValue(ai, raw);
  const confidence = getConfidence(ai);
  const historicalMatches = getHistoricalMatches(ai, pattern);
  const mitreTechniques = extractMitreTechniques(alert);
  const hashes = extractHashes(alert);
  const networkIndicators = extractNetworkIndicators(alert);
  const process = extractProcess(alert);
  const username = extractUsername(alert);
  const parentApplication = extractParentProcess(alert);
  const attackChain = buildAttackChain(alert);
  const iocs = extractIoCs(alert);

  const campaignTags = campaignMetadata.campaignTags || [];
  const riskFactors = campaignMetadata.attackPatterns || [];
  const correlationId = campaignMetadata.campaignDetected
    ? `campaign-${extractAgentName(alert)
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")}-${Date.now()}`
    : "";

  const existingIncident = await Incident.findOne({ incidentKey });

  if (!existingIncident) {
    return Incident.create({
      incidentKey,
      tenant_id: ai?.tenant_id || ai?.tenantId || raw.tenant_id || "tenant_1",
      source: "wazuh",
      correlationId,
      agentId: extractAgentId(alert),
      title,
      host: extractAgentName(alert),
      ip: extractAgentIp(alert),
      os: extractOs(alert),
      severity,
      priority,
      tier: incidentType,
      incidentType: classification,
      verdict: normalizedAnalystDecision || normalizeVerdict(ai?.verdict),
      aiConfidence: confidence,
      riskScore,
      riskFactors,
      historicalMatches,
      falsePositiveRate: getFpRate(ai, pattern),
      threatIntel,
      recommendedAction:
        campaignMetadata.recommendedAction ||
        ai?.recommended_action ||
        ai?.recommendedAction ||
        "",
      lastSeen: alert.timestamp || alert.createdAt || raw.timestamp || new Date(),
      firstSeen: alert.timestamp || alert.createdAt || raw.timestamp || new Date(),
      status,
      assigned: "",
      classification,
      timeline: [timelineEvent],
      notes: note ? [note] : [],
      analystNotes: note ? [note] : [],
      evidence: [evidence],
      relatedAlerts: [String(alert._id)],
      relatedIncidents,
      playbooks,
      attackChain,
      mitreTechniques,
      indicators: [
        ...new Set([
          ...hashes,
          ...networkIndicators,
          ...iocs.ips,
          ...iocs.domains,
          ...iocs.urls,
        ]),
      ],
      hashes,
      domains: iocs.domains,
      urls: iocs.urls,
      iocs: [...new Set([...iocs.ips, ...iocs.domains, ...iocs.urls])],
      processes: process && process !== "-" ? [process] : [],
      users: username && username !== "-" ? [username] : [],
      parentApplications: parentApplication && parentApplication !== "-" ? [parentApplication] : [],
      networkConnections: networkIndicators,
      sourceIPs: iocs.ips,
      destinationIPs: [],
      tags: campaignTags,
      enrichment: {
        campaign: campaignMetadata,
        investigation: investigationEnrichment,
      },
      autoCloseEligible: false,
      suppressionCandidate: false,
      requiresHumanReview:
        incidentType === "security" ||
        incidentType === "investigation" ||
        severity === "Critical" ||
        severity === "High" ||
        campaignMetadata.campaignDetected,
      escalationStatus:
        campaignMetadata.campaignDetected && campaignMetadata.correlatedIncidentCount >= 3
          ? "campaign_escalation"
          : incidentType === "security"
          ? "escalation_required"
          : "pending",
      closedAt: null,
    });
  }

  existingIncident.riskScore = Math.max(existingIncident.riskScore || 0, riskScore);
  existingIncident.severity = getSeverity(existingIncident.riskScore, incidentType, alert);

  if (campaignMetadata.campaignDetected && campaignMetadata.correlatedIncidentCount >= 3) {
    existingIncident.severity = "Critical";
  }

  existingIncident.priority = getPriority(existingIncident.severity);
  existingIncident.lastSeen = alert.timestamp || alert.createdAt || raw.timestamp || new Date();

  if (!existingIncident.correlationId && correlationId) {
    existingIncident.correlationId = correlationId;
  }

  existingIncident.verdict =
    normalizedAnalystDecision ||
    normalizeVerdict(ai?.verdict) ||
    existingIncident.verdict;

  existingIncident.aiConfidence = Math.max(existingIncident.aiConfidence || 0, confidence);

  existingIncident.historicalMatches = Math.max(
    existingIncident.historicalMatches || 0,
    historicalMatches
  );

  existingIncident.falsePositiveRate = Math.max(
    existingIncident.falsePositiveRate || 0,
    getFpRate(ai, pattern)
  );

  existingIncident.threatIntel = threatIntel;

  existingIncident.recommendedAction =
    campaignMetadata.recommendedAction ||
    ai?.recommended_action ||
    ai?.recommendedAction ||
    existingIncident.recommendedAction ||
    "";

  existingIncident.status =
    existingIncident.status === "Closed" ? existingIncident.status : status || existingIncident.status;

  existingIncident.escalationStatus =
    campaignMetadata.campaignDetected && campaignMetadata.correlatedIncidentCount >= 3
      ? "campaign_escalation"
      : incidentType === "security"
      ? "escalation_required"
      : existingIncident.escalationStatus || "pending";

  existingIncident.requiresHumanReview =
    existingIncident.requiresHumanReview ||
    incidentType === "security" ||
    incidentType === "investigation" ||
    existingIncident.severity === "Critical" ||
    existingIncident.severity === "High" ||
    campaignMetadata.campaignDetected;

  existingIncident.timeline = Array.isArray(existingIncident.timeline)
    ? existingIncident.timeline
    : [];
  existingIncident.timeline.push(timelineEvent);

  if (note) {
    existingIncident.notes = Array.isArray(existingIncident.notes)
      ? existingIncident.notes
      : [];
    existingIncident.analystNotes = Array.isArray(existingIncident.analystNotes)
      ? existingIncident.analystNotes
      : [];

    existingIncident.notes.push(note);
    existingIncident.analystNotes.push(note);
  }

  existingIncident.evidence = Array.isArray(existingIncident.evidence)
    ? existingIncident.evidence
    : [];
  existingIncident.evidence.push(evidence);

  existingIncident.relatedAlerts = mergeUnique(existingIncident.relatedAlerts, [
    String(alert._id),
  ]);

  existingIncident.relatedIncidents = relatedIncidents;

  existingIncident.playbooks = Array.isArray(existingIncident.playbooks)
    ? existingIncident.playbooks
    : [];

  playbooks.forEach((playbook) => {
    const exists = existingIncident.playbooks.some((item) => item.title === playbook.title);
    if (!exists) existingIncident.playbooks.push(playbook);
  });

  existingIncident.attackChain = mergeUnique(existingIncident.attackChain, attackChain);

  existingIncident.mitreTechniques = mergeUnique(
    existingIncident.mitreTechniques,
    mitreTechniques
  );

  existingIncident.indicators = mergeUnique(existingIncident.indicators, [
    ...hashes,
    ...networkIndicators,
    ...iocs.ips,
    ...iocs.domains,
    ...iocs.urls,
  ]);

  existingIncident.hashes = mergeUnique(existingIncident.hashes, hashes);
  existingIncident.domains = mergeUnique(existingIncident.domains, iocs.domains);
  existingIncident.urls = mergeUnique(existingIncident.urls, iocs.urls);
  existingIncident.iocs = mergeUnique(existingIncident.iocs, [
    ...iocs.ips,
    ...iocs.domains,
    ...iocs.urls,
  ]);

  if (process && process !== "-") {
    existingIncident.processes = mergeUnique(existingIncident.processes, [process]);
  }

  if (username && username !== "-") {
    existingIncident.users = mergeUnique(existingIncident.users, [username]);
  }

  if (parentApplication && parentApplication !== "-") {
    existingIncident.parentApplications = mergeUnique(
      existingIncident.parentApplications,
      [parentApplication]
    );
  }

  existingIncident.networkConnections = mergeUnique(
    existingIncident.networkConnections,
    networkIndicators
  );

  existingIncident.sourceIPs = mergeUnique(existingIncident.sourceIPs, iocs.ips);
  existingIncident.tags = mergeUnique(existingIncident.tags, campaignTags);
  existingIncident.riskFactors = mergeUnique(existingIncident.riskFactors, riskFactors);

  existingIncident.enrichment = {
    ...(existingIncident.enrichment || {}),
    campaign: campaignMetadata,
    investigation: investigationEnrichment,
  };

  await existingIncident.save();

  return existingIncident;
}

module.exports = {
  createOrUpdateIncident,
  getIncidentType,
  getSeverity,
  getPriority,
};