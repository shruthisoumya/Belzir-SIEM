const Anthropic = require("@anthropic-ai/sdk");

const anthropic = new Anthropic({
  apiKey: process.env.CLAUDE_API_KEY,
});

const CLAUDE_MAX_RETRIES = Number(process.env.CLAUDE_MAX_RETRIES || 2);
const CLAUDE_RETRY_BASE_MS = Number(process.env.CLAUDE_RETRY_BASE_MS || 15000);

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function getClaudeStatsStore() {
  global.belzirClaudeCacheStats = global.belzirClaudeCacheStats || {
    enabled: true,
    totalRequests: 0,
    claudeRequests: 0,
    fallbackRequests: 0,
    rateLimitedFallbacks: 0,
    cacheHits: 0,
    cacheMisses: 0,
    inputTokens: 0,
    outputTokens: 0,
    cacheCreationInputTokens: 0,
    cacheReadInputTokens: 0,
    lastUsage: null,
    lastUpdated: null,
  };

  return global.belzirClaudeCacheStats;
}

function trackClaudeUsage(usage = {}) {
  const stats = getClaudeStatsStore();

  const inputTokens = Number(usage.input_tokens || 0);
  const outputTokens = Number(usage.output_tokens || 0);
  const cacheCreationInputTokens = Number(usage.cache_creation_input_tokens || 0);
  const cacheReadInputTokens = Number(usage.cache_read_input_tokens || 0);

  stats.totalRequests += 1;
  stats.claudeRequests += 1;
  stats.inputTokens += inputTokens;
  stats.outputTokens += outputTokens;
  stats.cacheCreationInputTokens += cacheCreationInputTokens;
  stats.cacheReadInputTokens += cacheReadInputTokens;

  if (cacheReadInputTokens > 0) {
    stats.cacheHits += 1;
  } else {
    stats.cacheMisses += 1;
  }

  stats.lastUsage = {
    input_tokens: inputTokens,
    output_tokens: outputTokens,
    cache_creation_input_tokens: cacheCreationInputTokens,
    cache_read_input_tokens: cacheReadInputTokens,
  };

  stats.lastUpdated = new Date().toISOString();

  return stats;
}

function trackFallbackUsage({ rateLimited = false } = {}) {
  const stats = getClaudeStatsStore();

  stats.totalRequests += 1;
  stats.fallbackRequests += 1;

  if (rateLimited) {
    stats.rateLimitedFallbacks += 1;
  }

  stats.lastUpdated = new Date().toISOString();

  return stats;
}

function getClaudeCacheStats() {
  const stats = getClaudeStatsStore();

  const cacheableRequests = stats.cacheHits + stats.cacheMisses;

  return {
    ...stats,
    cacheHitRate:
      cacheableRequests > 0
        ? Number(((stats.cacheHits / cacheableRequests) * 100).toFixed(2))
        : 0,
    cacheMissRate:
      cacheableRequests > 0
        ? Number(((stats.cacheMisses / cacheableRequests) * 100).toFixed(2))
        : 0,
    totalTokens:
      Number(stats.inputTokens || 0) +
      Number(stats.outputTokens || 0) +
      Number(stats.cacheCreationInputTokens || 0) +
      Number(stats.cacheReadInputTokens || 0),
  };
}

const SOC_CACHE_PADDING = Array(120)
  .fill(
    `
Belzir-SIEM stable SOC triage policy:
- Analyze Wazuh alerts using rule level, rule id, rule description, agent, user, process, command line, MITRE, alert history, false positive rate, asset criticality, and threat intelligence.
- Classify only as false_positive, true_positive, or needs_review.
- Treat routine login, logout, PAM, sudo, session opened, session closed, audit success, and software protection events as benign unless suspicious context exists.
- Treat PowerShell encoded commands, credential theft, LSASS access, Mimikatz, ransomware, malware, brute force, failed authentication bursts, lateral movement, C2, persistence, privilege escalation, suspicious scripts, and unknown executable behavior as higher risk.
- Risk must be 0 to 100.
- Confidence must be 0.0 to 1.0.
- Return short SOC reasoning.
- Return only JSON.
`
  )
  .join("\n");

const CACHED_SOC_SYSTEM_PROMPT = `
You are SOC AI for Belzir-SIEM.

You analyze Wazuh alerts for an AI-driven SOC/SIEM platform.

Return ONLY valid JSON. No markdown. No extra text.

Decision rules:
- Use "false_positive" only when the alert is clearly benign, routine, expected system activity, or historically noisy with low risk.
- Use "true_positive" when there is credible malicious or high-risk security activity.
- Use "needs_review" when evidence is suspicious, incomplete, conflicting, or requires human validation.
- Do not escalate routine low-level Windows service/logon/logoff/audit noise unless suspicious context exists.
- Confidence must be dynamic between 0.0 and 1.0.
- Low-risk routine events should not automatically become investigations.
- Critical asset, MITRE technique, suspicious process, command line, threat intel, credential theft, lateral movement, persistence, malware, or PowerShell abuse should increase risk.
- High false-positive history should reduce confidence unless critical asset or threat intel exists.
- Prefer short SOC reasoning.
- Risk must be 0 to 100.

Return JSON only in this exact structure:
{
  "verdict": "true_positive | false_positive | needs_review",
  "confidence": 0.0,
  "reasoning": "short SOC reasoning",
  "recommended_action": "short SOC action",
  "requires_human_review": true,
  "risk": 0
}

${SOC_CACHE_PADDING}
`;

function extractJson(text) {
  if (!text) return null;

  try {
    return JSON.parse(text);
  } catch (err) {
    const match = text.match(/\{[\s\S]*\}/);
    if (!match) return null;

    try {
      return JSON.parse(match[0]);
    } catch (innerErr) {
      return null;
    }
  }
}

function safeString(value, fallback = "unknown") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value).replace(/"/g, '\\"').slice(0, 600);
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

function normalizeConfidence(value) {
  let confidence = Number(value);
  if (Number.isNaN(confidence)) return 0.3;
  if (confidence > 1) confidence = confidence / 100;
  return Math.max(0.05, Math.min(0.99, Number(confidence.toFixed(2))));
}

function extractProcess(alert) {
  const raw = alert.rawAlert || {};
  return (
    raw.data?.win?.eventdata?.processName ||
    raw.data?.win?.eventdata?.image ||
    raw.data?.win?.eventdata?.newProcessName ||
    raw.data?.win?.eventdata?.processCommandLine ||
    raw.data?.win?.eventdata?.commandLine ||
    raw.data?.audit?.exe ||
    raw.data?.process ||
    raw.decoder?.name ||
    "unknown"
  );
}

function extractUsername(alert) {
  const raw = alert.rawAlert || {};
  return (
    raw.data?.win?.eventdata?.targetUserName ||
    raw.data?.win?.eventdata?.subjectUserName ||
    raw.data?.win?.eventdata?.targetDomainName ||
    raw.data?.audit?.uid ||
    raw.data?.srcuser ||
    raw.data?.dstuser ||
    "unknown"
  );
}

function extractCommandLine(alert) {
  const raw = alert.rawAlert || {};
  return (
    raw.data?.win?.eventdata?.commandLine ||
    raw.data?.win?.eventdata?.processCommandLine ||
    raw.data?.commandLine ||
    raw.data?.command_line ||
    raw.data?.command ||
    "unknown"
  );
}

function extractMitre(alert) {
  const raw = alert.rawAlert || {};
  const mitre = raw.rule?.mitre || raw.mitre || {};

  return {
    ids: Array.isArray(mitre.id) ? mitre.id : mitre.id ? [mitre.id] : [],
    tactics: Array.isArray(mitre.tactic)
      ? mitre.tactic
      : mitre.tactic
      ? [mitre.tactic]
      : [],
    techniques: Array.isArray(mitre.technique)
      ? mitre.technique
      : mitre.technique
      ? [mitre.technique]
      : [],
  };
}

function extractIndicators(text = "") {
  const indicators = [];
  const ips = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  const hashes = text.match(/\b[a-fA-F0-9]{32,64}\b/g) || [];
  const domains = text.match(/\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g) || [];

  indicators.push(...ips, ...hashes, ...domains);
  return [...new Set(indicators.filter(Boolean))];
}

function detectThreatIntel(alertText = "") {
  const text = alertText.toLowerCase();

  const maliciousKeywords = [
    "mimikatz",
    "credential dumping",
    "lsass",
    "powershell",
    "encodedcommand",
    "ransomware",
    "c2",
    "command and control",
    "trojan",
    "malware",
    "persistence",
    "privilege escalation",
    "lateral movement",
    "brute force",
    "reverse shell",
  ];

  const matches = maliciousKeywords.filter((keyword) => text.includes(keyword));

  return {
    hits: matches,
    malicious: matches.length > 0,
  };
}

function buildAttackChain(alertText = "") {
  const text = alertText.toLowerCase();
  const chain = [];

  if (text.includes("powershell")) chain.push("Execution - PowerShell");
  if (text.includes("encodedcommand")) chain.push("Defense Evasion - Encoded Commands");
  if (text.includes("credential")) chain.push("Credential Access");
  if (text.includes("lsass")) chain.push("Credential Dumping");
  if (text.includes("lateral movement")) chain.push("Lateral Movement");
  if (text.includes("persistence")) chain.push("Persistence");
  if (text.includes("c2") || text.includes("command and control")) {
    chain.push("Command and Control");
  }

  return [...new Set(chain)];
}

function buildCompactRawAlert(alert) {
  const raw = alert.rawAlert || {};

  return {
    timestamp: raw.timestamp || alert.timestamp || alert.createdAt,
    rule: raw.rule || {
      id: alert.ruleId,
      level: alert.ruleLevel,
      description: alert.ruleDescription,
    },
    agent: raw.agent || {
      id: alert.agentId,
      name: alert.agentName,
    },
    location: raw.location || alert.location,
    decoder: raw.decoder,
    eventdata: raw.data?.win?.eventdata,
    data: raw.data,
  };
}

function isRateLimitError(err) {
  const status = err?.status || err?.response?.status;
  const message = String(err?.message || err?.error?.message || "").toLowerCase();

  return (
    status === 429 ||
    message.includes("429") ||
    message.includes("rate_limit") ||
    message.includes("rate limit")
  );
}

function getRetryDelay(err, attempt) {
  const headers = err?.headers || err?.response?.headers || {};
  const retryAfter = headers["retry-after"] || headers["Retry-After"];

  if (retryAfter) {
    const seconds = Number(retryAfter);
    if (!Number.isNaN(seconds)) return Math.max(1000, seconds * 1000);
  }

  return CLAUDE_RETRY_BASE_MS * Math.pow(2, attempt);
}

async function callClaudeWithRetry(payload) {
  let lastError = null;

  for (let attempt = 0; attempt <= CLAUDE_MAX_RETRIES; attempt += 1) {
    try {
      return await anthropic.messages.create(payload);
    } catch (err) {
      lastError = err;

      if (!isRateLimitError(err) || attempt >= CLAUDE_MAX_RETRIES) {
        throw err;
      }

      const delay = getRetryDelay(err, attempt);

      console.warn(
        `Claude rate limit hit. Retry ${attempt + 1}/${CLAUDE_MAX_RETRIES} after ${delay}ms`
      );

      await sleep(delay);
    }
  }

  throw lastError;
}

function lightweightFallback({
  alert,
  threatIntelResult,
  indicators,
  attackChain,
  reason = "Fallback AI analysis completed.",
}) {
  const raw = alert.rawAlert || {};
  const ruleLevel = raw.rule?.level || alert.ruleLevel || 0;
  const description = (raw.rule?.description || alert.ruleDescription || "").toLowerCase();

  let verdict = "needs_investigation";
  let confidence = 0.45;
  let risk = Math.min(100, Number(ruleLevel) * 8) || 20;

  if (
    description.includes("successful sudo") ||
    description.includes("pam") ||
    description.includes("session opened") ||
    description.includes("session closed") ||
    description.includes("software protection service scheduled successfully") ||
    description.includes("authentication success")
  ) {
    verdict = "false_positive";
    confidence = 0.88;
    risk = 5;
  }

  if (
    description.includes("netstat") ||
    description.includes("listened ports status")
  ) {
    verdict = "needs_investigation";
    confidence = 0.55;
    risk = Math.max(risk, 45);
  }

  if (threatIntelResult.malicious) {
    verdict = "true_positive";
    confidence = 0.92;
    risk = Math.max(risk, 85);
  }

  if (description.includes("powershell") || description.includes("encoded")) {
    verdict = "needs_investigation";
    confidence = 0.72;
    risk = Math.max(risk, 80);
  }

  const rateLimited = reason.toLowerCase().includes("rate limit");

  trackFallbackUsage({ rateLimited });

  return {
    verdict,
    confidence,
    reasoning: threatIntelResult.malicious
      ? `Threat indicators detected: ${threatIntelResult.hits.join(", ")}`
      : reason,
    recommended_action:
      verdict === "true_positive"
        ? "Escalate and investigate immediately."
        : verdict === "false_positive"
        ? "Suppress recurring benign activity if validated."
        : "Collect more telemetry and validate activity.",
    requires_human_review: verdict !== "false_positive",
    historical_matches: 0,
    threat_intel: threatIntelResult.malicious
      ? threatIntelResult.hits
      : "No malicious IOC found.",
    indicators,
    attack_chain: attackChain,
    risk,
    fp_rate: 0,
    tp_count: 0,
    asset_criticality: "MEDIUM",
    ai_provider: rateLimited ? "rate-limit-fallback" : "fallback",
    ai_model: "local-heuristic",
    cache_control_enabled: false,
    claude_rate_limited: rateLimited,
    pattern_key: `${safeString(alert.ruleDescription || "unknown-rule")}-${safeString(
      alert.agentName || "unknown-agent"
    )}`
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-"),
    suppression_candidate: verdict === "false_positive",
    auto_close_eligible: verdict === "false_positive",
    dangerous_pattern: threatIntelResult.malicious,
    create_investigation_incident: verdict !== "false_positive",
  };
}

async function analyzeAlertWithClaude({
  alert,
  tenant = "tenant_1",
  similarAlerts = 0,
  falsePositiveRate = 0,
  assetCriticality = "UNKNOWN",
  threatIntel = "No threat intelligence available.",
}) {
  const model = process.env.CLAUDE_MODEL || "claude-haiku-4-5-20251001";

  const ruleLevel = alert.ruleLevel || alert.rawAlert?.rule?.level || 0;
  const ruleId = alert.rawAlert?.rule?.id || alert.ruleId || "unknown";
  const ruleDescription =
    alert.ruleDescription || alert.rawAlert?.rule?.description || "Unknown Wazuh alert";
  const agentName = alert.agentName || alert.rawAlert?.agent?.name || "unknown-agent";

  const processName = extractProcess(alert);
  const username = extractUsername(alert);
  const commandLine = extractCommandLine(alert);
  const mitre = extractMitre(alert);
  const compactRawAlert = buildCompactRawAlert(alert);
  const rawText = JSON.stringify(compactRawAlert);
  const indicators = extractIndicators(rawText);
  const threatIntelResult = detectThreatIntel(rawText);
  const attackChain = buildAttackChain(rawText);

  if (!process.env.CLAUDE_API_KEY) {
    return lightweightFallback({
      alert,
      threatIntelResult,
      indicators,
      attackChain,
      reason: "Claude API key missing. Local fallback analysis completed.",
    });
  }

  const dynamicAlertContext = `
Tenant:
${safeString(tenant)}

Alert:
{
  "rule_id": "${safeString(ruleId)}",
  "rule_level": ${Number(ruleLevel || 0)},
  "rule_description": "${safeString(ruleDescription)}",
  "agent": "${safeString(agentName)}",
  "process": "${safeString(processName)}",
  "username": "${safeString(username)}",
  "command_line": "${safeString(commandLine)}",
  "mitre_ids": ${JSON.stringify(mitre.ids)},
  "mitre_tactics": ${JSON.stringify(mitre.tactics)},
  "mitre_techniques": ${JSON.stringify(mitre.techniques)},
  "similar_alerts": ${Number(similarAlerts || 0)},
  "false_positive_rate": ${Number(falsePositiveRate || 0)},
  "asset_criticality": "${safeString(assetCriticality)}",
  "threat_intel": "${safeString(threatIntel)}"
}
`;

  try {
    const response = await callClaudeWithRetry({
      model,
      max_tokens: 140,
      temperature: 0,
      system: [
        {
          type: "text",
          text: CACHED_SOC_SYSTEM_PROMPT,
          cache_control: {
            type: "ephemeral",
          },
        },
      ],
      messages: [
        {
          role: "user",
          content: [
            {
              type: "text",
              text: dynamicAlertContext,
            },
          ],
        },
      ],
    });

    const usage = response.usage || {};
    const stats = trackClaudeUsage(usage);

    console.log("Claude cache usage:", {
      input_tokens: usage.input_tokens || 0,
      output_tokens: usage.output_tokens || 0,
      cache_creation_input_tokens: usage.cache_creation_input_tokens || 0,
      cache_read_input_tokens: usage.cache_read_input_tokens || 0,
      cache_hits: stats.cacheHits,
      cache_misses: stats.cacheMisses,
      cache_hit_rate: getClaudeCacheStats().cacheHitRate,
    });

    const text =
      response.content
        ?.map((block) => (block.type === "text" ? block.text : ""))
        .join("\n")
        .trim() || "";

    const parsed = extractJson(text);

    if (!parsed) {
      return lightweightFallback({
        alert,
        threatIntelResult,
        indicators,
        attackChain,
        reason: "Claude response was not valid JSON. Local fallback analysis completed.",
      });
    }

    const verdict = normalizeVerdict(parsed.verdict);

    return {
      verdict,
      confidence: normalizeConfidence(parsed.confidence),
      reasoning: parsed.reasoning || "Claude analysis completed.",
      recommended_action: parsed.recommended_action || "Review incident.",
      requires_human_review: parsed.requires_human_review ?? true,
      historical_matches: Number(similarAlerts || 0),
      threat_intel: threatIntelResult.malicious ? threatIntelResult.hits : threatIntel,
      indicators,
      attack_chain: attackChain,
      risk: Number(parsed.risk || 0) || Math.min(100, ruleLevel * 8),
      fp_rate: Number(falsePositiveRate || 0),
      tp_count: 0,
      asset_criticality: assetCriticality,
      ai_provider: "claude",
      ai_model: model,
      cache_control_enabled: true,
      claude_cache: {
        input_tokens: usage.input_tokens || 0,
        output_tokens: usage.output_tokens || 0,
        cache_creation_input_tokens: usage.cache_creation_input_tokens || 0,
        cache_read_input_tokens: usage.cache_read_input_tokens || 0,
        cache_hits: stats.cacheHits,
        cache_misses: stats.cacheMisses,
        cache_hit_rate: getClaudeCacheStats().cacheHitRate,
      },
      pattern_key: `${safeString(ruleDescription)}-${safeString(agentName)}-${safeString(
        processName
      )}`
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-"),
      suppression_candidate: false,
      auto_close_eligible: false,
      dangerous_pattern: threatIntelResult.malicious,
      create_investigation_incident: verdict !== "false_positive",
    };
  } catch (err) {
    const rateLimited = isRateLimitError(err);

    console.error(
      rateLimited ? "Claude rate limit fallback:" : "Claude API fallback:",
      err.message
    );

    return lightweightFallback({
      alert,
      threatIntelResult,
      indicators,
      attackChain,
      reason: rateLimited
        ? "Claude rate limit reached after retries. Local fallback analysis completed."
        : "Claude API error. Local fallback analysis completed.",
    });
  }
}

module.exports = {
  analyzeAlertWithClaude,
  getClaudeCacheStats,
};