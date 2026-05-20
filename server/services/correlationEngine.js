const Incident = require("../models/Incident");

const CORRELATION_WINDOW_MINUTES = 120;
const MAX_RELATED_INCIDENTS = 25;
const REPEATED_ALERT_CAMPAIGN_THRESHOLD = 5;
const REPEATED_EVIDENCE_CAMPAIGN_THRESHOLD = 5;

function safeString(value, fallback = "") {
  if (value === null || value === undefined) return fallback;
  return String(value).trim();
}

function uniqueArray(values = []) {
  return [...new Set(values.filter(Boolean))];
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

function extractAgentName(alert = {}) {
  const raw = alert.rawAlert || {};

  return alert.agentName || alert.agent || raw.agent?.name || "unknown-agent";
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
    ""
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
    ""
  );
}

function extractCommandLine(alert = {}) {
  const raw = alert.rawAlert || {};

  return (
    raw.data?.win?.eventdata?.commandLine ||
    raw.data?.win?.eventdata?.processCommandLine ||
    raw.process?.command_line ||
    raw.command_line ||
    ""
  );
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
    ...(Array.isArray(mitre.tactic)
      ? mitre.tactic
      : mitre.tactic
      ? [mitre.tactic]
      : []),
  ];

  return uniqueArray(techniques);
}

function extractHashes(alert = {}) {
  const raw = alert.rawAlert || {};

  const hashes = [
    raw.data?.win?.eventdata?.hashes,
    raw.data?.win?.eventdata?.hash,
    raw.data?.hash,
    raw.syscheck?.sha256_after,
    raw.syscheck?.md5_after,
  ];

  const flattened = [];

  hashes.forEach((item) => {
    if (!item) return;

    if (typeof item === "string") {
      item
        .split(",")
        .map((x) => x.trim())
        .filter(Boolean)
        .forEach((x) => flattened.push(x));
    }

    if (Array.isArray(item)) {
      item.filter(Boolean).forEach((x) => flattened.push(x));
    }
  });

  return uniqueArray(flattened);
}

function extractIoCs(alert = {}) {
  const raw = alert.rawAlert || {};
  const text = JSON.stringify(raw);

  const ips = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  const domains = text.match(/\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g) || [];
  const urls = text.match(/https?:\/\/[^\s"]+/g) || [];

  return {
    ips: uniqueArray(ips),
    domains: uniqueArray(domains),
    urls: uniqueArray(urls),
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
    hasKeyword(alert, [
      "powershell",
      "encodedcommand",
      "encoded command",
      "iex",
      "invoke-expression",
      "downloadstring",
      "frombase64string",
    ])
  ) {
    detections.push("POWERSHELL_ATTACK");
  }

  if (
    hasKeyword(alert, [
      "mimikatz",
      "credential dumping",
      "credential dump",
      "lsass",
      "sekurlsa",
    ])
  ) {
    detections.push("CREDENTIAL_ACCESS");
  }

  if (
    hasKeyword(alert, [
      "lateral movement",
      "psexec",
      "wmic",
      "remote execution",
      "remote service",
    ])
  ) {
    detections.push("LATERAL_MOVEMENT");
  }

  if (
    hasKeyword(alert, [
      "c2",
      "command and control",
      "beacon",
      "reverse shell",
      "callback",
    ])
  ) {
    detections.push("COMMAND_AND_CONTROL");
  }

  return uniqueArray(detections);
}

function buildCampaignTags(alert = {}) {
  const attackPatterns = detectAttackPatterns(alert);
  const mitre = extractMitreTechniques(alert);
  const hashes = extractHashes(alert);
  const iocs = extractIoCs(alert);
  const process = extractProcess(alert);

  return uniqueArray([
    ...attackPatterns,
    ...mitre,
    ...hashes,
    ...iocs.domains,
    ...iocs.urls,
    process,
  ]);
}

function buildIncidentKey(alert = {}, incidentType = "investigation") {
  const rule = extractRuleDescription(alert);
  const agent = extractAgentName(alert);

  return `${incidentType}-${agent}-${rule}`
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 180);
}

function calculateCorrelationScore({
  incident,
  host,
  ip,
  username,
  process,
  commandLine,
  mitreTechniques,
  hashes,
  attackPatterns,
  iocs,
}) {
  let score = 0;

  if (host && incident.host && host === incident.host) {
    score += 30;
  }

  if (
    ip &&
    (incident.ip === ip ||
      incident.sourceIPs?.includes(ip) ||
      incident.destinationIPs?.includes(ip) ||
      incident.networkConnections?.includes(ip))
  ) {
    score += 25;
  }

  if (
    username &&
    Array.isArray(incident.users) &&
    incident.users.includes(username)
  ) {
    score += 20;
  }

  if (
    process &&
    Array.isArray(incident.processes) &&
    incident.processes.includes(process)
  ) {
    score += 15;
  }

  if (
    commandLine &&
    Array.isArray(incident.evidence) &&
    incident.evidence.some((evidence) =>
      safeString(evidence.command_line)
        .toLowerCase()
        .includes(commandLine.toLowerCase())
    )
  ) {
    score += 10;
  }

  const incidentMitre = incident.mitreTechniques || [];
  const sharedMitre = mitreTechniques.filter((item) =>
    incidentMitre.includes(item)
  );

  score += sharedMitre.length * 12;

  const incidentIndicators = incident.indicators || [];

  hashes.forEach((hash) => {
    if (incidentIndicators.includes(hash)) {
      score += 18;
    }
  });

  attackPatterns.forEach((pattern) => {
    if (
      Array.isArray(incident.tags) &&
      incident.tags.includes(pattern)
    ) {
      score += 12;
    }

    if (
      Array.isArray(incident.riskFactors) &&
      incident.riskFactors.includes(pattern)
    ) {
      score += 12;
    }
  });

  [...iocs.ips, ...iocs.domains, ...iocs.urls].forEach((ioc) => {
    if (incidentIndicators.includes(ioc)) {
      score += 15;
    }
  });

  if (Array.isArray(incident.relatedAlerts) && incident.relatedAlerts.length >= 5) {
    score += 20;
  }

  if (Array.isArray(incident.evidence) && incident.evidence.length >= 5) {
    score += 20;
  }

  return score;
}

function determineCampaignSeverity(score = 0) {
  if (score >= 120) return "Critical";
  if (score >= 80) return "High";
  if (score >= 40) return "Medium";
  return "Low";
}

function determineCampaignConfidence(score = 0) {
  if (score >= 120) return 0.95;
  if (score >= 80) return 0.85;
  if (score >= 40) return 0.7;
  return 0.5;
}

async function findCurrentIncident(alert = {}) {
  const possibleKeys = [
    buildIncidentKey(alert, "security"),
    buildIncidentKey(alert, "investigation"),
    buildIncidentKey(alert, "detection_tuning"),
    buildIncidentKey(alert, "operational"),
    buildIncidentKey(alert, "ai_quality"),
  ];

  return Incident.findOne({
    incidentKey: { $in: possibleKeys },
  });
}

function buildRepeatedAlertMetadata(currentIncident = null) {
  if (!currentIncident) {
    return {
      repeatedAlertDetected: false,
      repeatedAlertCount: 0,
      repeatedEvidenceCount: 0,
    };
  }

  const repeatedAlertCount = Array.isArray(currentIncident.relatedAlerts)
    ? currentIncident.relatedAlerts.length
    : 0;

  const repeatedEvidenceCount = Array.isArray(currentIncident.evidence)
    ? currentIncident.evidence.length
    : 0;

  return {
    repeatedAlertDetected:
      repeatedAlertCount >= REPEATED_ALERT_CAMPAIGN_THRESHOLD ||
      repeatedEvidenceCount >= REPEATED_EVIDENCE_CAMPAIGN_THRESHOLD,

    repeatedAlertCount,
    repeatedEvidenceCount,
  };
}

async function findCorrelatedIncidents(alert = {}) {
  const host = extractAgentName(alert);
  const ip = extractAgentIp(alert);
  const username = extractUsername(alert);
  const process = extractProcess(alert);
  const commandLine = extractCommandLine(alert);

  const mitreTechniques = extractMitreTechniques(alert);
  const hashes = extractHashes(alert);
  const attackPatterns = detectAttackPatterns(alert);
  const iocs = extractIoCs(alert);

  const correlationWindow = new Date(
    Date.now() - CORRELATION_WINDOW_MINUTES * 60 * 1000
  );

  const orConditions = [];

  if (host) orConditions.push({ host });
  if (ip) {
    orConditions.push({ ip });
    orConditions.push({ sourceIPs: ip });
    orConditions.push({ destinationIPs: ip });
    orConditions.push({ networkConnections: ip });
  }
  if (username) orConditions.push({ users: username });
  if (process) orConditions.push({ processes: process });
  if (mitreTechniques.length > 0) {
    orConditions.push({ mitreTechniques: { $in: mitreTechniques } });
  }
  if (hashes.length > 0) {
    orConditions.push({ indicators: { $in: hashes } });
  }
  if (iocs.ips.length > 0) {
    orConditions.push({ indicators: { $in: iocs.ips } });
  }
  if (iocs.domains.length > 0) {
    orConditions.push({ indicators: { $in: iocs.domains } });
  }
  if (iocs.urls.length > 0) {
    orConditions.push({ indicators: { $in: iocs.urls } });
  }
  if (attackPatterns.length > 0) {
    orConditions.push({ tags: { $in: attackPatterns } });
    orConditions.push({ riskFactors: { $in: attackPatterns } });
  }

  if (orConditions.length === 0) {
    return [];
  }

  const incidents = await Incident.find({
    updatedAt: {
      $gte: correlationWindow,
    },
    $or: orConditions,
  })
    .sort({ updatedAt: -1 })
    .limit(MAX_RELATED_INCIDENTS);

  const correlatedIncidents = incidents
    .map((incident) => {
      const score = calculateCorrelationScore({
        incident,
        host,
        ip,
        username,
        process,
        commandLine,
        mitreTechniques,
        hashes,
        attackPatterns,
        iocs,
      });

      return {
        _id: incident._id,
        incidentKey: incident.incidentKey,
        title: incident.title,
        severity: incident.severity,
        status: incident.status,
        riskScore: incident.riskScore,
        score,
        relatedAlertCount: Array.isArray(incident.relatedAlerts)
          ? incident.relatedAlerts.length
          : 0,
        evidenceCount: Array.isArray(incident.evidence)
          ? incident.evidence.length
          : 0,
        correlationReasons: {
          sameHost: host && incident.host && host === incident.host,

          sameIP:
            ip &&
            (incident.ip === ip ||
              incident.sourceIPs?.includes(ip) ||
              incident.destinationIPs?.includes(ip) ||
              incident.networkConnections?.includes(ip)),

          sameUser:
            username &&
            Array.isArray(incident.users) &&
            incident.users.includes(username),

          sameProcess:
            process &&
            Array.isArray(incident.processes) &&
            incident.processes.includes(process),

          repeatedAlerts:
            Array.isArray(incident.relatedAlerts) &&
            incident.relatedAlerts.length >= REPEATED_ALERT_CAMPAIGN_THRESHOLD,

          repeatedEvidence:
            Array.isArray(incident.evidence) &&
            incident.evidence.length >= REPEATED_EVIDENCE_CAMPAIGN_THRESHOLD,

          sharedMitre: mitreTechniques.filter((item) =>
            (incident.mitreTechniques || []).includes(item)
          ),

          sharedHashes: hashes.filter((item) =>
            (incident.indicators || []).includes(item)
          ),

          sharedAttackPatterns: attackPatterns.filter(
            (item) =>
              (incident.tags || []).includes(item) ||
              (incident.riskFactors || []).includes(item)
          ),
        },
      };
    })
    .filter((incident) => incident.score >= 20)
    .sort((a, b) => b.score - a.score);

  return correlatedIncidents;
}

async function buildCampaignMetadata(alert = {}) {
  const [correlatedIncidents, currentIncident] = await Promise.all([
    findCorrelatedIncidents(alert),
    findCurrentIncident(alert),
  ]);

  const repeatedAlertMetadata = buildRepeatedAlertMetadata(currentIncident);

  const totalScore = correlatedIncidents.reduce(
    (sum, incident) => sum + incident.score,
    0
  );

  const attackPatterns = detectAttackPatterns(alert);
  const campaignTags = buildCampaignTags(alert);

  const repeatedAlertRiskBoost = repeatedAlertMetadata.repeatedAlertDetected
    ? Math.min(
        50,
        repeatedAlertMetadata.repeatedAlertCount * 6 +
          repeatedAlertMetadata.repeatedEvidenceCount * 4
      )
    : 0;

  const campaignRisk =
    totalScore + attackPatterns.length * 15 + repeatedAlertRiskBoost;

  const campaignDetected =
    correlatedIncidents.length >= 2 ||
    repeatedAlertMetadata.repeatedAlertDetected;

  const correlatedIncidentCount = correlatedIncidents.length;

  const repeatedReason =
    repeatedAlertMetadata.repeatedAlertDetected
      ? `Repeated alert behavior detected inside same incident (${repeatedAlertMetadata.repeatedAlertCount} related alerts, ${repeatedAlertMetadata.repeatedEvidenceCount} evidence records).`
      : "";

  return {
    campaignDetected,

    repeatedAlertDetected: repeatedAlertMetadata.repeatedAlertDetected,

    repeatedAlertCount: repeatedAlertMetadata.repeatedAlertCount,

    repeatedEvidenceCount: repeatedAlertMetadata.repeatedEvidenceCount,

    correlatedIncidentCount,

    campaignSeverity: determineCampaignSeverity(campaignRisk),

    campaignConfidence: determineCampaignConfidence(campaignRisk),

    campaignRisk,

    attackPatterns,

    campaignTags,

    correlatedIncidents,

    correlationSummary: {
      sameIncidentRepeatedActivity: repeatedAlertMetadata.repeatedAlertDetected,
      separateIncidentCorrelation: correlatedIncidents.length >= 2,
      repeatedReason,
    },

    recommendedAction:
      correlatedIncidents.length >= 3
        ? "Escalate as coordinated attack campaign"
        : repeatedAlertMetadata.repeatedAlertDetected
        ? "Investigate repeated suspicious behavior on same asset and validate whether this is automation, test activity, or active attack progression"
        : correlatedIncidents.length >= 1
        ? "Review related incidents for attack progression"
        : "Monitor for additional correlated activity",
  };
}

module.exports = {
  findCorrelatedIncidents,
  buildCampaignMetadata,
  detectAttackPatterns,
  extractMitreTechniques,
  extractHashes,
  extractIoCs,
  buildCampaignTags,
};