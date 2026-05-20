import React, { useEffect, useMemo, useState } from "react";
import SiemLayout from "../components/siem/SiemLayout";
import "../styles/Hunt.css";

const API_BASE = "http://10.0.3.83:5000";

export default function Hunt() {
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [patterns, setPatterns] = useState([]);
  const [activeTab, setActiveTab] = useState("all");
  const [timeRange, setTimeRange] = useState("all");
  const [expandedId, setExpandedId] = useState(null);
  const [loading, setLoading] = useState(true);

  const getArray = (payload) => {
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.data)) return payload.data;
    if (Array.isArray(payload?.incidents)) return payload.incidents;
    if (Array.isArray(payload?.alerts)) return payload.alerts;
    if (Array.isArray(payload?.patterns)) return payload.patterns;
    return [];
  };

  const cleanText = (value) => {
    const text = String(value || "-");

    if (
      text.toLowerCase().includes("claude api error") ||
      text.toLowerCase().includes("rate_limit_error") ||
      text.toLowerCase().includes("429")
    ) {
      return "AI rate limit fallback. Saved alert context is available for analyst review.";
    }

    return text;
  };

  const safeNumber = (value, fallback = 0) => {
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
  };

  const normalizeText = (value) =>
    String(value || "")
      .toLowerCase()
      .trim();

  const formatDateTime = (value) => {
    if (!value || value === "-") return "-";

    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;

    return date.toLocaleString("en-GB", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  const formatConfidence = (value) => {
    const number = safeNumber(value);
    if (number <= 1) return `${Math.round(number * 100)}%`;
    return `${Math.round(number)}%`;
  };

  const normalizeMitre = (value) => {
    if (Array.isArray(value)) return value.filter(Boolean);
    if (!value || value === "-") return [];
    return [value];
  };

  const getSeverity = (risk, value) => {
    const normalized = normalizeText(value);

    if (normalized.includes("critical")) return "CRITICAL";
    if (normalized.includes("high")) return "HIGH";
    if (normalized.includes("medium")) return "MEDIUM";
    if (normalized.includes("low")) return "LOW";

    if (risk >= 85) return "CRITICAL";
    if (risk >= 70) return "HIGH";
    if (risk >= 40) return "MEDIUM";
    return "LOW";
  };

  const getStatus = (item) => {
    const verdict = normalizeText(item.verdict);
    const status = normalizeText(item.status);

    if (
      status.includes("dismiss") ||
      verdict.includes("false_positive") ||
      verdict.includes("benign")
    ) {
      return "DISMISSED";
    }

    if (
      status.includes("confirm") ||
      verdict.includes("true_positive") ||
      verdict.includes("malicious")
    ) {
      return "CONFIRMED";
    }

    if (item.signalCount > 0 || item.hitCount > 0 || item.risk >= 70) {
      return "HIT";
    }

    return "MISS";
  };

  const getStatusClass = (status) => {
    const normalized = normalizeText(status);
    if (normalized.includes("confirmed")) return "confirmed";
    if (normalized.includes("dismissed")) return "dismissed";
    if (normalized.includes("hit")) return "hit";
    return "miss";
  };

  const withinRange = (timestamp) => {
    if (timeRange === "all") return true;

    const date = new Date(timestamp || 0);
    if (Number.isNaN(date.getTime())) return false;

    const now = Date.now();
    const diff = now - date.getTime();

    if (timeRange === "24h") return diff <= 24 * 60 * 60 * 1000;
    if (timeRange === "3d") return diff <= 3 * 24 * 60 * 60 * 1000;
    if (timeRange === "7d") return diff <= 7 * 24 * 60 * 60 * 1000;
    if (timeRange === "30d") return diff <= 30 * 24 * 60 * 60 * 1000;

    return true;
  };

  useEffect(() => {
    let cancelled = false;

    async function loadHuntData() {
      try {
        setLoading(true);

        const [alertsRes, incidentsRes, patternsRes] = await Promise.all([
          fetch(`${API_BASE}/api/wazuh/analyst-queue?limit=50`),
          fetch(`${API_BASE}/api/incidents?limit=5`),
          fetch(`${API_BASE}/api/wazuh/alert-patterns?limit=50`),
        ]);

        const [alertsData, incidentsData, patternsData] = await Promise.all([
          alertsRes.json(),
          incidentsRes.json(),
          patternsRes.json(),
        ]);

        if (cancelled) return;

        setAlerts(getArray(alertsData));
        setIncidents(getArray(incidentsData));
        setPatterns(getArray(patternsData));
      } catch (err) {
        console.error("Hunt fetch error:", err);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    loadHuntData();

    const interval = setInterval(loadHuntData, 120000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const extractIncidentEvidence = (incident) => {
    if (Array.isArray(incident.evidence)) return incident.evidence;
    return [];
  };

  const huntItems = useMemo(() => {
    const alertItems = alerts.map((alert, index) => {
      const raw = alert.rawAlert || alert.raw || {};
      const mitre = normalizeMitre(
        raw?.rule?.mitre?.id ||
          raw?.rule?.mitre?.technique ||
          alert.mitre ||
          alert.mitreTechniques
      );

      const risk = safeNumber(alert.risk || alert.riskScore || alert.finalRisk || alert.aiRisk);

      return {
        id: alert.alert_id || alert.id || alert._id || `alert-${index}`,
        source: "alert",
        title:
          alert.hunt_title ||
          alert.huntTitle ||
          alert.rule_description ||
          alert.ruleDescription ||
          alert.title ||
          raw?.rule?.description ||
          "-",
        description:
          alert.hunt_summary ||
          alert.summary ||
          alert.reasoning ||
          alert.ai_reasoning ||
          alert.rule_description ||
          raw?.rule?.description ||
          "-",
        host: alert.agent || alert.agentName || raw?.agent?.name || "-",
        user:
          alert.username ||
          raw?.data?.srcuser ||
          raw?.data?.dstuser ||
          raw?.data?.win?.eventdata?.targetUserName ||
          "-",
        process:
          alert.process ||
          raw?.data?.win?.eventdata?.image ||
          raw?.data?.processName ||
          "-",
        command:
          raw?.data?.win?.eventdata?.commandLine ||
          raw?.data?.win?.eventdata?.processCommandLine ||
          raw?.data?.command ||
          "-",
        mitre,
        technique: mitre[0] || "-",
        ip: raw?.data?.srcip || raw?.data?.dstip || raw?.agent?.ip || "-",
        hash: raw?.data?.hash || raw?.data?.sha256 || raw?.data?.md5 || "-",
        risk,
        severity: getSeverity(risk, alert.severity),
        confidence: safeNumber(alert.confidence || alert.aiConfidence),
        verdict: alert.verdict || alert.ai_verdict || "-",
        status: alert.status || alert.decision || alert.verdict || "-",
        reasoning: cleanText(alert.reasoning || alert.ai_reasoning || "-"),
        recommendedAction: cleanText(
          alert.recommended_action || alert.recommendedAction || "-"
        ),
        timestamp: alert.timestamp || alert.createdAt || alert.updatedAt || "-",
        raw: alert,
      };
    });

    const incidentItems = incidents.flatMap((incident, index) => {
      const evidence = extractIncidentEvidence(incident);

      if (evidence.length === 0) {
        const risk = safeNumber(incident.riskScore || incident.risk || incident.finalRisk);

        return [
          {
            id: incident._id || incident.incidentKey || `incident-${index}`,
            source: "incident",
            title: incident.title || incident.incidentKey || "-",
            description:
              incident.summary ||
              incident.classification ||
              incident.incidentType ||
              incident.recommendedAction ||
              "-",
            host: incident.host || incident.agent || "-",
            user: Array.isArray(incident.users) ? incident.users.join(", ") : "-",
            process: Array.isArray(incident.processes)
              ? incident.processes.join(", ")
              : "-",
            command: "-",
            mitre: normalizeMitre(incident.mitreTechniques),
            technique: normalizeMitre(incident.mitreTechniques)[0] || "-",
            ip: incident.ip || "-",
            hash: "-",
            risk,
            severity: getSeverity(risk, incident.severity),
            confidence: safeNumber(incident.aiConfidence || incident.confidence),
            verdict: incident.verdict || "-",
            status: incident.status || incident.verdict || "-",
            reasoning: cleanText(incident.classification || incident.incidentType || "-"),
            recommendedAction: cleanText(incident.recommendedAction || "-"),
            timestamp: incident.lastSeen || incident.updatedAt || incident.createdAt || "-",
            raw: incident,
          },
        ];
      }

      return evidence.map((ev, evIndex) => {
        const risk = safeNumber(ev.risk || incident.riskScore || incident.risk);

        const mitre = normalizeMitre(ev.mitre_techniques || incident.mitreTechniques);

        return {
          id: `${incident._id || incident.incidentKey || index}-${ev.alert_id || ev.rule_id || evIndex}`,
          source: "incident",
          title: incident.title || ev.rule_description || "-",
          description:
            ev.reasoning ||
            ev.rule_description ||
            incident.summary ||
            incident.classification ||
            "-",
          host: ev.agent || incident.host || "-",
          user: ev.username || "-",
          process: ev.process || "-",
          command: ev.command_line || "-",
          mitre,
          technique: mitre[0] || "-",
          ip: ev.source_ip || ev.destination_ip || incident.ip || "-",
          hash: Array.isArray(ev.hashes) ? ev.hashes.join(", ") : "-",
          risk,
          severity: getSeverity(risk, incident.severity),
          confidence: safeNumber(ev.confidence || incident.aiConfidence),
          verdict: ev.verdict || incident.verdict || "-",
          status: incident.status || ev.verdict || "-",
          reasoning: cleanText(ev.reasoning || incident.classification || "-"),
          recommendedAction: cleanText(
            ev.recommended_action || incident.recommendedAction || "-"
          ),
          timestamp: incident.lastSeen || incident.updatedAt || incident.createdAt || "-",
          raw: { incident, evidence: ev },
        };
      });
    });

    return [...alertItems, ...incidentItems];
  }, [alerts, incidents]);

  const patternMap = useMemo(() => {
    const map = new Map();

    patterns.forEach((pattern) => {
      const key = String(
        pattern.pattern_key ||
          pattern.patternKey ||
          pattern.rule_description ||
          pattern.title ||
          ""
      ).toLowerCase();

      if (key) map.set(key, pattern);
    });

    return map;
  }, [patterns]);

  const enrichedItems = useMemo(() => {
    return huntItems.map((item) => {
      const titleKey = String(item.title || "")
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-");

      const hostKey = String(item.host || "")
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-");

      const processKey = String(item.process || "")
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-");

      let relatedPattern = null;

      for (const [key, pattern] of patternMap.entries()) {
        if (
          (titleKey && key.includes(titleKey)) ||
          (hostKey && key.includes(hostKey)) ||
          (processKey && key.includes(processKey))
        ) {
          relatedPattern = pattern;
          break;
        }
      }

      const lowerProcess = normalizeText(item.process);
      const lowerCommand = normalizeText(item.command);
      const lowerVerdict = normalizeText(item.verdict);
      const lowerTitle = normalizeText(item.title);
      const lowerDescription = normalizeText(item.description);

      const suspiciousSignals = [
        item.risk >= 70 ? "risk" : null,
        lowerProcess.includes("powershell") ? "process" : null,
        lowerCommand.includes("-enc") ? "command" : null,
        lowerCommand.includes("encodedcommand") ? "command" : null,
        lowerCommand.includes("downloadstring") ? "command" : null,
        lowerCommand.includes("invoke") ? "command" : null,
        lowerTitle.includes("lateral") || lowerDescription.includes("lateral")
          ? "lateral movement"
          : null,
        lowerTitle.includes("persistence") || lowerDescription.includes("persistence")
          ? "persistence"
          : null,
        lowerTitle.includes("ransomware") || lowerDescription.includes("ransomware")
          ? "ransomware"
          : null,
        lowerVerdict.includes("true_positive") ? "verdict" : null,
        relatedPattern?.dangerous_pattern || relatedPattern?.dangerousPattern
          ? "pattern"
          : null,
      ].filter(Boolean);

      const hitCount = Math.max(
        suspiciousSignals.length,
        safeNumber(relatedPattern?.tp_count || relatedPattern?.tpCount),
        item.risk >= 70 ? 1 : 0
      );

      const output = {
        ...item,
        pattern: relatedPattern,
        suspiciousSignals,
        signalCount: suspiciousSignals.length,
        hitCount,
      };

      return {
        ...output,
        huntStatus: getStatus(output),
      };
    });
  }, [huntItems, patternMap]);

  const filteredItems = useMemo(() => {
    return enrichedItems
      .filter((item) => withinRange(item.timestamp))
      .filter((item) => {
        const status = getStatus(item);

        if (activeTab === "all") return true;
        if (activeTab === "hits") return status === "HIT";
        if (activeTab === "miss") return status === "MISS";
        if (activeTab === "confirmed") return status === "CONFIRMED";
        if (activeTab === "dismissed") return status === "DISMISSED";

        return true;
      })
      .sort((a, b) => {
        const dateA = new Date(a.timestamp || 0).getTime();
        const dateB = new Date(b.timestamp || 0).getTime();

        if (dateB !== dateA) return dateB - dateA;
        return b.risk - a.risk;
      });
  }, [enrichedItems, activeTab, timeRange]);

  const counts = useMemo(() => {
    return {
      all: enrichedItems.filter((item) => withinRange(item.timestamp)).length,
      hits: enrichedItems.filter(
        (item) => withinRange(item.timestamp) && getStatus(item) === "HIT"
      ).length,
      miss: enrichedItems.filter(
        (item) => withinRange(item.timestamp) && getStatus(item) === "MISS"
      ).length,
      confirmed: enrichedItems.filter(
        (item) => withinRange(item.timestamp) && getStatus(item) === "CONFIRMED"
      ).length,
      dismissed: enrichedItems.filter(
        (item) => withinRange(item.timestamp) && getStatus(item) === "DISMISSED"
      ).length,
    };
  }, [enrichedItems, timeRange]);

  const tabs = [
    { key: "all", label: `All (${counts.all})` },
    { key: "hits", label: `Hits (${counts.hits})` },
    { key: "miss", label: "Miss" },
    { key: "confirmed", label: "Confirmed" },
    { key: "dismissed", label: "Dismissed" },
  ];

  const ranges = [
    { key: "24h", label: "24H" },
    { key: "3d", label: "3D" },
    { key: "7d", label: "7D" },
    { key: "30d", label: "30D" },
    { key: "all", label: "ALL" },
  ];

  return (
    <SiemLayout>
      <div className="hunt-page">
        <div className="hunt-toolbar">
          <div className="hunt-tabs">
            {tabs.map((tab) => (
              <button
                key={tab.key}
                className={activeTab === tab.key ? "active" : ""}
                onClick={() => {
                  setActiveTab(tab.key);
                  setExpandedId(null);
                }}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className="hunt-actions">
            <div className="hunt-ranges">
              {ranges.map((range) => (
                <button
                  key={range.key}
                  className={timeRange === range.key ? "active" : ""}
                  onClick={() => {
                    setTimeRange(range.key);
                    setExpandedId(null);
                  }}
                >
                  {range.label}
                </button>
              ))}
            </div>

            <button className="run-hunt-btn">Run Hunt</button>
          </div>
        </div>

        <div className="hunt-list">
          {loading ? (
            <div className="hunt-empty">Loading hunt results...</div>
          ) : filteredItems.length === 0 ? (
            <div className="hunt-empty">No hunt results found.</div>
          ) : (
            filteredItems.map((item) => {
              const expanded = expandedId === item.id;
              const status = getStatus(item);
              const statusClass = getStatusClass(status);

              return (
                <div className={expanded ? "hunt-card expanded" : "hunt-card"} key={item.id}>
                  <div
                    className="hunt-row"
                    onClick={() => setExpandedId(expanded ? null : item.id)}
                  >
                    <div className="hunt-main">
                      <div className="hunt-line">
                        <span className={`hunt-chip ${statusClass}`}>
                          {status === "HIT" ? `HIT ${item.hitCount || 1}` : status}
                        </span>

                        <span className={`hunt-severity ${normalizeText(item.severity)}`}>
                          {item.severity}
                        </span>

                        {item.technique !== "-" && (
                          <span className="hunt-technique">{item.technique}</span>
                        )}

                        <h3>{item.title}</h3>
                      </div>

                      <p>
                        {status === "MISS"
                          ? "No indicators found."
                          : `Found ${item.hitCount || item.signalCount || 1} indicator(s).`}
                      </p>

                      {expanded && (
                        <div className="hunt-expanded-short">
                          <span className={`hunt-chip ${statusClass}`}>{status}</span>
                          <span>{formatDateTime(item.timestamp)}</span>
                        </div>
                      )}
                    </div>

                    <div className="hunt-right">
                      {!expanded && status !== "MISS" && (
                        <span className={`hunt-status-badge ${statusClass}`}>{status}</span>
                      )}

                      <span>{formatDateTime(item.timestamp)}</span>
                      <strong>{expanded ? "▲" : "▼"}</strong>
                    </div>
                  </div>

                  {expanded && (
                    <div className="hunt-expanded">
                      <div className="hunt-detail-grid">
                        <div className="hunt-detail-box">
                          <h4>Hunt Finding</h4>
                          <p>{item.description}</p>
                        </div>

                        <div className="hunt-detail-box">
                          <h4>Reasoning</h4>
                          <p>{item.reasoning}</p>
                        </div>
                      </div>

                      <div className="hunt-section">
                        <h4>Indicators</h4>
                        <div className="hunt-indicator-grid">
                          <div>
                            <label>Host</label>
                            <span>{item.host}</span>
                          </div>

                          <div>
                            <label>User</label>
                            <span>{item.user}</span>
                          </div>

                          <div>
                            <label>Process</label>
                            <span>{item.process}</span>
                          </div>

                          <div>
                            <label>IP</label>
                            <span>{item.ip}</span>
                          </div>

                          <div>
                            <label>Hash</label>
                            <span>{item.hash}</span>
                          </div>

                          <div>
                            <label>Confidence</label>
                            <span>{formatConfidence(item.confidence)}</span>
                          </div>
                        </div>
                      </div>

                      <div className="hunt-section">
                        <h4>Command / Evidence</h4>
                        <pre>{item.command}</pre>
                      </div>

                      <div className="hunt-section">
                        <h4>MITRE Mapping</h4>
                        <p>
                          {Array.isArray(item.mitre) && item.mitre.length > 0
                            ? item.mitre.join(", ")
                            : "-"}
                        </p>
                      </div>

                      <div className="hunt-section">
                        <h4>Recommended Action</h4>
                        <p>{item.recommendedAction}</p>
                      </div>

                      {item.suspiciousSignals.length > 0 && (
                        <div className="hunt-tags">
                          {item.suspiciousSignals.map((signal, index) => (
                            <span key={`${item.id}-${signal}-${index}`}>{signal}</span>
                          ))}
                        </div>
                      )}

                      <div className="hunt-footer">
                        <span className={`hunt-chip ${statusClass}`}>{status}</span>
                        <span>{formatDateTime(item.timestamp)}</span>
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </SiemLayout>
  );
}