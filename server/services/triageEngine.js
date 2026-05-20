const { analyzeAlertWithClaude } = require("./claudeService");

function toNumber(value, fallback = 0) {
  const number = Number(value);
  return Number.isNaN(number) ? fallback : number;
}

function normalizeVerdict(verdict) {
  if (verdict === "true_positive") return "true_positive";
  if (verdict === "false_positive") return "false_positive";
  if (verdict === "needs_investigation") return "needs_investigation";
  if (verdict === "needs_review") return "needs_investigation";
  if (verdict === "tp") return "true_positive";
  if (verdict === "fp") return "false_positive";
  if (verdict === "investigate") return "needs_investigation";
  return "needs_investigation";
}

function getRaw(alert) {
  return alert.rawAlert || alert.raw || alert || {};
}

function getRawText(alert) {
  return JSON.stringify(getRaw(alert)).toLowerCase();
}

function getMitreData(alert) {
  const raw = getRaw(alert);
  const mitre = raw.rule?.mitre || raw.mitre || {};

  const ids = Array.isArray(mitre.id) ? mitre.id : mitre.id ? [mitre.id] : [];
  const tactics = Array.isArray(mitre.tactic)
    ? mitre.tactic
    : mitre.tactic
    ? [mitre.tactic]
    : [];
  const techniques = Array.isArray(mitre.technique)
    ? mitre.technique
    : mitre.technique
    ? [mitre.technique]
    : [];

  return {
    ids,
    tactics,
    techniques,
  };
}

function hasMitre(alert) {
  const mitre = getMitreData(alert);

  return (
    mitre.ids.length > 0 ||
    mitre.tactics.length > 0 ||
    mitre.techniques.length > 0
  );
}

function hasHighRiskMitre(alert) {
  const mitre = getMitreData(alert);

  const text = [...mitre.ids, ...mitre.tactics, ...mitre.techniques]
    .join(" ")
    .toLowerCase();

  return (
    text.includes("credential") ||
    text.includes("privilege escalation") ||
    text.includes("persistence") ||
    text.includes("defense evasion") ||
    text.includes("lateral") ||
    text.includes("execution") ||
    text.includes("command and control") ||
    text.includes("exfiltration")
  );
}

function extractProcess(alert) {
  const raw = getRaw(alert);

  return (
    raw.data?.win?.eventdata?.processName ||
    raw.data?.win?.eventdata?.image ||
    raw.data?.win?.eventdata?.newProcessName ||
    raw.data?.win?.eventdata?.commandLine ||
    raw.data?.win?.eventdata?.processCommandLine ||
    raw.data?.audit?.exe ||
    raw.data?.audit?.command ||
    raw.data?.process ||
    raw.decoder?.name ||
    "-"
  );
}

function extractUsername(alert) {
  const raw = getRaw(alert);

  return (
    raw.data?.win?.eventdata?.targetUserName ||
    raw.data?.win?.eventdata?.subjectUserName ||
    raw.data?.srcuser ||
    raw.data?.dstuser ||
    raw.data?.user ||
    raw.data?.audit?.uid ||
    "-"
  );
}

function extractSourceIp(alert) {
  const raw = getRaw(alert);

  return (
    raw.data?.srcip ||
    raw.data?.src_ip ||
    raw.data?.source_ip ||
    raw.data?.win?.eventdata?.sourceIp ||
    raw.data?.win?.eventdata?.ipAddress ||
    raw.agent?.ip ||
    "-"
  );
}

function extractDestinationIp(alert) {
  const raw = getRaw(alert);

  return (
    raw.data?.dstip ||
    raw.data?.dst_ip ||
    raw.data?.destination_ip ||
    raw.data?.win?.eventdata?.destinationIp ||
    "-"
  );
}

function extractCommandLine(alert) {
  const raw = getRaw(alert);

  return (
    raw.data?.win?.eventdata?.commandLine ||
    raw.data?.win?.eventdata?.processCommandLine ||
    raw.data?.commandLine ||
    raw.data?.command_line ||
    "-"
  );
}

function extractIndicators(alert) {
  const text = JSON.stringify(getRaw(alert));

  const ips = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  const hashes = text.match(/\b[a-fA-F0-9]{32,64}\b/g) || [];
  const domains = text.match(/\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g) || [];
  const urls = text.match(/https?:\/\/[^\s"]+/g) || [];

  return {
    ips: [...new Set(ips)],
    hashes: [...new Set(hashes)],
    domains: [...new Set(domains)],
    urls: [...new Set(urls)],
    all: [...new Set([...ips, ...hashes, ...domains, ...urls])],
  };
}

function hasSuspiciousSecuritySignal(alert) {
  const text = getRawText(alert);

  return (
    text.includes("credential dumping") ||
    text.includes("mimikatz") ||
    text.includes("lsass") ||
    text.includes("lateral movement") ||
    text.includes("pass the hash") ||
    text.includes("command and control") ||
    text.includes("encodedcommand") ||
    text.includes("encoded command") ||
    text.includes("malware") ||
    text.includes("ransomware") ||
    text.includes("persistence") ||
    text.includes("privilege escalation") ||
    text.includes("unauthorized") ||
    text.includes("brute force") ||
    text.includes("exploit") ||
    text.includes("backdoor") ||
    text.includes("reverse shell") ||
    text.includes("beacon")
  );
}

function hasSuspiciousProcessLineage(alert) {
  const raw = getRaw(alert);

  const process =
    raw.data?.win?.eventdata?.processName ||
    raw.data?.win?.eventdata?.image ||
    raw.data?.win?.eventdata?.newProcessName ||
    raw.data?.win?.eventdata?.commandLine ||
    raw.data?.win?.eventdata?.processCommandLine ||
    raw.data?.audit?.exe ||
    raw.data?.audit?.command ||
    raw.decoder?.name ||
    "";

  const parent =
    raw.data?.win?.eventdata?.parentProcessName ||
    raw.data?.win?.eventdata?.parentImage ||
    "";

  const combined = `${process} ${parent}`.toLowerCase();

  return (
    combined.includes("powershell") ||
    combined.includes("cmd.exe") ||
    combined.includes("wscript") ||
    combined.includes("cscript") ||
    combined.includes("rundll32") ||
    combined.includes("regsvr32") ||
    combined.includes("mshta") ||
    combined.includes("bitsadmin") ||
    combined.includes("certutil") ||
    combined.includes("curl") ||
    combined.includes("wget")
  );
}

function isRoutineNoise(alert) {
  const text = getRawText(alert);
  const level = toNumber(getRaw(alert).rule?.level || alert.ruleLevel);

  const routine =
    text.includes("pam: login session opened") ||
    text.includes("pam: login session closed") ||
    text.includes("summary event of the report") ||
    text.includes("windows error reporting") ||
    text.includes("security configuration assessment scan finished") ||
    text.includes("syscollector") ||
    text.includes("rootcheck") ||
    text.includes("successful sudo to root executed");

  return routine && level <= 5 && !hasSuspiciousSecuritySignal(alert);
}

function detectAttackPatterns(alert) {
  const text = getRawText(alert);
  const patterns = [];

  if (
    text.includes("authentication failed") ||
    text.includes("failed password") ||
    text.includes("failed login") ||
    text.includes("invalid user") ||
    text.includes("brute force")
  ) {
    patterns.push("BRUTE_FORCE");
  }

  if (
    text.includes("powershell") ||
    text.includes("encodedcommand") ||
    text.includes("encoded command") ||
    text.includes("invoke-expression") ||
    text.includes("iex")
  ) {
    patterns.push("POWERSHELL_ATTACK");
  }

  if (
    text.includes("mimikatz") ||
    text.includes("credential dumping") ||
    text.includes("lsass") ||
    text.includes("sam database")
  ) {
    patterns.push("CREDENTIAL_ACCESS");
  }

  if (
    text.includes("psexec") ||
    text.includes("wmic") ||
    text.includes("remote execution") ||
    text.includes("lateral movement") ||
    text.includes("pass the hash")
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
    text.includes("ransomware") ||
    text.includes("trojan") ||
    text.includes("malware")
  ) {
    patterns.push("MALWARE");
  }

  if (
    text.includes("persistence") ||
    text.includes("scheduled task") ||
    text.includes("run key")
  ) {
    patterns.push("PERSISTENCE");
  }

  return [...new Set(patterns)];
}

function buildAttackChain(alert) {
  const patterns = detectAttackPatterns(alert);
  const chain = [];

  if (patterns.includes("BRUTE_FORCE")) chain.push("Initial Access");
  if (patterns.includes("POWERSHELL_ATTACK")) chain.push("Execution");
  if (patterns.includes("PERSISTENCE")) chain.push("Persistence");
  if (patterns.includes("CREDENTIAL_ACCESS")) chain.push("Credential Access");
  if (patterns.includes("LATERAL_MOVEMENT")) chain.push("Lateral Movement");
  if (patterns.includes("COMMAND_AND_CONTROL")) chain.push("Command and Control");
  if (patterns.includes("MALWARE")) chain.push("Impact");

  return [...new Set(chain)];
}

function calculateRisk(level, alert, pattern = null) {
  let risk = Math.min(100, Math.round((toNumber(level) / 15) * 100));

  if (isRoutineNoise(alert)) risk = Math.min(risk, 10);

  if (hasSuspiciousSecuritySignal(alert)) risk += 25;
  if (hasHighRiskMitre(alert)) risk += 20;
  else if (hasMitre(alert)) risk += 10;
  if (hasSuspiciousProcessLineage(alert)) risk += 15;

  const attackPatterns = detectAttackPatterns(alert);

  if (attackPatterns.includes("CREDENTIAL_ACCESS")) risk += 25;
  if (attackPatterns.includes("LATERAL_MOVEMENT")) risk += 25;
  if (attackPatterns.includes("COMMAND_AND_CONTROL")) risk += 25;
  if (attackPatterns.includes("POWERSHELL_ATTACK")) risk += 15;
  if (attackPatterns.includes("BRUTE_FORCE")) risk += 10;
  if (attackPatterns.includes("MALWARE")) risk += 25;
  if (attackPatterns.includes("PERSISTENCE")) risk += 15;

  if (pattern?.dangerous_pattern === true) risk += 15;

  if (toNumber(pattern?.fp_rate) > 0.9 && toNumber(pattern?.occurrences) > 50) {
    risk -= 15;
  }

  return Math.max(0, Math.min(100, Math.round(risk)));
}

function getAssetCriticality(alert) {
  const raw = getRaw(alert);

  const agentName = alert.agentName || raw.agent?.name || alert.agent?.name || "";
  const description = alert.ruleDescription || raw.rule?.description || "";
  const location = alert.location || raw.location || "";

  const text = `${agentName} ${description} ${location}`.toLowerCase();

  if (
    text.includes("server") ||
    text.includes("siem") ||
    text.includes("domain") ||
    text.includes("dc") ||
    text.includes("finance") ||
    text.includes("hr") ||
    text.includes("prod") ||
    text.includes("production") ||
    text.includes("critical")
  ) {
    return "HIGH";
  }

  return "MEDIUM";
}

function buildThreatIntel(alert) {
  const text = getRawText(alert);
  const indicators = extractIndicators(alert);

  const hits = [];

  if (text.includes("mimikatz")) hits.push("mimikatz");
  if (text.includes("lsass")) hits.push("lsass");
  if (text.includes("credential dumping")) hits.push("credential dumping");
  if (text.includes("lateral movement")) hits.push("lateral movement");
  if (text.includes("pass the hash")) hits.push("pass the hash");
  if (text.includes("command and control")) hits.push("command and control");
  if (text.includes("encodedcommand")) hits.push("encodedcommand");
  if (text.includes("malware")) hits.push("malware");
  if (text.includes("ransomware")) hits.push("ransomware");
  if (text.includes("privilege escalation")) hits.push("privilege escalation");
  if (text.includes("persistence")) hits.push("persistence");
  if (text.includes("brute force")) hits.push("brute force");
  if (text.includes("exploit")) hits.push("exploit");
  if (text.includes("reverse shell")) hits.push("reverse shell");

  if (hits.length > 0) {
    return {
      verdict: "suspicious",
      hits,
      indicators,
      summary: `Suspicious indicators found: ${hits.join(", ")}`,
    };
  }

  return {
    verdict: "clean",
    hits: [],
    indicators,
    summary: "No malicious IOC found.",
  };
}

function hasThreatIntelHit(threatIntel) {
  if (!threatIntel) return false;

  if (typeof threatIntel === "object") {
    return Array.isArray(threatIntel.hits) && threatIntel.hits.length > 0;
  }

  const text = String(threatIntel).toLowerCase();

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

function normalizeConfidence(value, risk, fpRate, occurrences, verdict, pattern) {
  let confidence = Number(value);

  if (Number.isNaN(confidence) || confidence <= 0) {
    confidence = 0.5;
  }

  if (confidence > 1) {
    confidence = confidence / 100;
  }

  const normalizedVerdict = normalizeVerdict(verdict);
  const normalizedFpRate = toNumber(fpRate);
  const normalizedOccurrences = toNumber(occurrences);

  confidence += Math.min(0.15, risk / 600);
  confidence += Math.min(0.1, normalizedOccurrences * 0.005);

  if (normalizedVerdict === "false_positive") {
    confidence -= Math.min(0.12, normalizedFpRate * 0.12);
  }

  if (normalizedVerdict === "true_positive" && risk >= 70) {
    confidence += 0.1;
  }

  if (normalizedVerdict === "true_positive" && pattern?.dangerous_pattern) {
    confidence += 0.1;
  }

  if (
    normalizedVerdict === "false_positive" &&
    normalizedFpRate > 0.9 &&
    normalizedOccurrences > 50
  ) {
    confidence += 0.08;
  }

  if (normalizedVerdict === "needs_investigation") {
    confidence = Math.min(confidence, 0.72);
  }

  return Number(Math.max(0.35, Math.min(0.98, confidence)).toFixed(2));
}

function getFallbackVerdict({
  risk,
  fpRate,
  occurrences,
  tpCount,
  pattern,
  threatIntel,
  routineNoise,
}) {
  if (routineNoise && risk <= 10 && fpRate >= 0.5) {
    return "false_positive";
  }

  if (pattern?.dangerous_pattern === true || tpCount > 0 || risk >= 75) {
    return "true_positive";
  }

  if (hasThreatIntelHit(threatIntel) && risk >= 50) {
    return "true_positive";
  }

  if (fpRate > 0.9 && occurrences > 50 && risk < 50) {
    return "false_positive";
  }

  if (routineNoise && risk <= 10) {
    return "false_positive";
  }

  return "needs_investigation";
}

function shouldCreateInvestigationIncident(aiResult) {
  const risk = toNumber(aiResult.risk);
  const confidence = toNumber(aiResult.confidence);
  const verdict = normalizeVerdict(aiResult.verdict);
  const fpRate = toNumber(aiResult.fp_rate);
  const occurrences = toNumber(aiResult.historical_matches);
  const threatIntelHit = hasThreatIntelHit(aiResult.threat_intel);

  if (verdict === "true_positive") return true;
  if (verdict === "false_positive") return false;
  if (aiResult.routine_noise === true && risk < 20) return false;

  if (threatIntelHit) return true;
  if (risk >= 40) return true;
  if (confidence < 0.7 && risk >= 30) return true;
  if (fpRate > 0.9 && occurrences > 50) return false;

  return false;
}

async function analyzeAlert(alert, pattern = null) {
  const level = alert.ruleLevel || getRaw(alert)?.rule?.level || 0;
  const risk = calculateRisk(level, alert, pattern);

  const occurrences = toNumber(pattern?.occurrences);
  const fpRate = toNumber(pattern?.fp_rate);
  const tpCount = toNumber(pattern?.tp_count);

  const assetCriticality = getAssetCriticality(alert);
  const threatIntel = buildThreatIntel(alert);
  const indicators = extractIndicators(alert);
  const attackPatterns = detectAttackPatterns(alert);
  const attackChain = buildAttackChain(alert);
  const routineNoise = isRoutineNoise(alert);

  try {
    const claudeResult = await analyzeAlertWithClaude({
      alert,
      tenant: alert.tenant || alert.tenant_id || "tenant_1",
      similarAlerts: occurrences,
      falsePositiveRate: fpRate,
      assetCriticality,
      threatIntel: threatIntel.summary || threatIntel,
    });

    let verdict = normalizeVerdict(claudeResult.verdict);

    if (routineNoise && risk <= 10 && verdict !== "true_positive") {
      verdict = "false_positive";
    }

    const result = {
      verdict,
      confidence: normalizeConfidence(
        claudeResult.confidence,
        risk,
        fpRate,
        occurrences,
        verdict,
        pattern
      ),
      reasoning:
        claudeResult.reasoning ||
        "AI analyzed alert using alert context, history, asset criticality, and threat intelligence.",
      recommended_action:
        claudeResult.recommended_action ||
        claudeResult.recommendedAction ||
        "Review alert and related events.",
      requires_human_review:
        verdict === "needs_investigation"
          ? true
          : claudeResult.requires_human_review ?? false,

      historical_matches: occurrences,
      threat_intel: threatIntel,
      indicators: indicators.all,
      malicious_ips: indicators.ips,
      malicious_hashes: indicators.hashes,
      suspicious_domains: indicators.domains,
      urls: indicators.urls,
      attack_patterns: attackPatterns,
      attack_chain: attackChain,
      risk,
      fp_rate: fpRate,
      tp_count: tpCount,
      asset_criticality: assetCriticality,
      ai_provider: claudeResult.ai_provider || "fallback",
      ai_model: claudeResult.ai_model || process.env.CLAUDE_MODEL || "local",
      pattern_key: pattern?.pattern_key || claudeResult.pattern_key || "",
      suppression_candidate:
        pattern?.suppression_candidate || claudeResult.suppression_candidate || false,
      auto_close_eligible:
        pattern?.auto_close_eligible || claudeResult.auto_close_eligible || false,
      dangerous_pattern:
        pattern?.dangerous_pattern ||
        claudeResult.dangerous_pattern ||
        hasThreatIntelHit(threatIntel),
      routine_noise: routineNoise,
    };

    result.create_investigation_incident = shouldCreateInvestigationIncident(result);

    return result;
  } catch (err) {
    console.error("Claude failed, using fallback:", err.message);

    const fallbackVerdict = getFallbackVerdict({
      risk,
      fpRate,
      occurrences,
      tpCount,
      pattern,
      threatIntel,
      routineNoise,
    });

    let fallbackConfidence = 0.45;

    if (risk >= 80) fallbackConfidence = 0.85;
    else if (risk >= 60) fallbackConfidence = 0.75;
    else if (risk >= 30) fallbackConfidence = 0.6;

    if (fallbackVerdict === "false_positive" && fpRate > 0.9 && occurrences > 50) {
      fallbackConfidence = 0.82;
    }

    if (fallbackVerdict === "false_positive" && routineNoise) {
      fallbackConfidence = 0.9;
    }

    if (fallbackVerdict === "needs_investigation") {
      fallbackConfidence = Math.min(fallbackConfidence, 0.65);
    }

    const result = {
      verdict: fallbackVerdict,
      confidence: Number(fallbackConfidence.toFixed(2)),
      reasoning:
        "Fallback triage used alert risk, pattern history, threat context, asset criticality, and local correlation.",
      recommended_action:
        fallbackVerdict === "true_positive"
          ? "Escalate as security incident and preserve evidence."
          : fallbackVerdict === "false_positive"
          ? "Validate false-positive pattern and review suppression safety."
          : "Investigate alert context, user, host, process, indicators, and related events.",
      requires_human_review: fallbackVerdict !== "false_positive",
      historical_matches: occurrences,
      threat_intel: threatIntel,
      indicators: indicators.all,
      malicious_ips: indicators.ips,
      malicious_hashes: indicators.hashes,
      suspicious_domains: indicators.domains,
      urls: indicators.urls,
      attack_patterns: attackPatterns,
      attack_chain: attackChain,
      risk,
      fp_rate: fpRate,
      tp_count: tpCount,
      asset_criticality: assetCriticality,
      ai_provider: "fallback",
      ai_model: process.env.CLAUDE_MODEL || "local",
      pattern_key: pattern?.pattern_key || "",
      suppression_candidate: pattern?.suppression_candidate || false,
      auto_close_eligible: pattern?.auto_close_eligible || false,
      dangerous_pattern: pattern?.dangerous_pattern || hasThreatIntelHit(threatIntel),
      routine_noise: routineNoise,
    };

    result.create_investigation_incident = shouldCreateInvestigationIncident(result);

    return result;
  }
}

module.exports = analyzeAlert;