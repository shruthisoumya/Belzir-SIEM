import React, { useEffect, useMemo, useState } from "react";
import SiemLayout from "../components/siem/SiemLayout";
import "../styles/Incidents.css";

const API_BASE = "http://10.0.3.83:5000";

export default function Incidents() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("All");
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [search, setSearch] = useState("");
  const [detailTab, setDetailTab] = useState("Overview");
  const [lastUpdated, setLastUpdated] = useState(null);
  const [decisionLoading, setDecisionLoading] = useState(false);
  const [error, setError] = useState("");

  const safeNumber = (value, fallback = 0) => {
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
  };

  const toArray = (value) => {
    if (Array.isArray(value)) return value.filter(Boolean);
    if (value === null || value === undefined || value === "") return [];
    return [value];
  };

  const getPayloadArray = (payload) => {
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.data)) return payload.data;
    if (Array.isArray(payload?.incidents)) return payload.incidents;
    if (Array.isArray(payload?.results)) return payload.results;
    if (Array.isArray(payload?.items)) return payload.items;
    return [];
  };

  const getFirstValue = (...values) => {
    for (const value of values) {
      if (Array.isArray(value) && value.length > 0) return value[0];
      if (value !== null && value !== undefined && value !== "") return value;
    }
    return "-";
  };

  const normalizeStatus = (status) => {
    const value = String(status || "open").toLowerCase();

    if (value.includes("investigating")) return "investigating";
    if (value.includes("investigation")) return "investigating";
    if (value.includes("under")) return "investigating";
    if (value.includes("review")) return "investigating";
    if (value.includes("resolved")) return "resolved";
    if (value.includes("closed")) return "resolved";
    if (value.includes("false_positive")) return "resolved";
    if (value.includes("false positive")) return "resolved";

    return "open";
  };

  const formatConfidence = (value) => {
    if (value === null || value === undefined || value === "-") return "-";

    const number = Number(value);

    if (Number.isNaN(number)) return String(value);
    if (number <= 1) return `${Math.round(number * 100)}%`;

    return `${Math.round(number)}%`;
  };

  const formatDateTime = (value) => {
    if (!value || value === "-") return "-";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) return String(value);

    return date.toLocaleString("en-GB", {
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const normalizeListValue = (item) => {
    if (item === null || item === undefined || item === "") return "-";

    if (typeof item === "string" || typeof item === "number") {
      return String(item);
    }

    if (typeof item === "object") {
      return (
        item.name ||
        item.value ||
        item.ip ||
        item.domain ||
        item.hash ||
        item.technique ||
        item.techniqueId ||
        item.id ||
        item.title ||
        item.description ||
        item.action ||
        JSON.stringify(item)
      );
    }

    return String(item);
  };

  const getEvidenceAlertId = (incident) => {
    const evidence = Array.isArray(incident?.evidence) ? incident.evidence : [];
    const relatedAlerts = Array.isArray(incident?.relatedAlerts)
      ? incident.relatedAlerts
      : [];

    return (
      evidence[0]?.alert_id ||
      evidence[0]?.alertId ||
      evidence[0]?._id ||
      relatedAlerts[0]?.alert_id ||
      relatedAlerts[0]?.alertId ||
      relatedAlerts[0]?._id ||
      incident?.alert_id ||
      incident?.alertId ||
      incident?.sourceAlertId ||
      incident?.source_alert_id ||
      incident?.id ||
      incident?._id ||
      null
    );
  };

  const normalizeIncident = (item, index) => {
    const evidence = Array.isArray(item?.evidence) ? item.evidence : [];
    const relatedAlerts = Array.isArray(item?.relatedAlerts)
      ? item.relatedAlerts
      : Array.isArray(item?.related_alerts)
      ? item.related_alerts
      : [];
    const timeline = Array.isArray(item?.timeline) ? item.timeline : [];
    const playbooks = Array.isArray(item?.playbooks) ? item.playbooks : [];

    const riskScore = safeNumber(item.riskScore ?? item.risk ?? item.finalRisk ?? 0);

    const threatIntel = Array.isArray(item.threatIntel)
      ? item.threatIntel.join(", ")
      : item.threatIntel || item.threat_intel || "No threat intelligence available.";

    return {
      ...item,

      _id: item._id || item.id || `incident-${index}`,
      incidentKey:
        item.incidentKey ||
        item.incident_key ||
        item.key ||
        item.id ||
        item._id ||
        `incident-${index}`,

      title:
        item.title ||
        item.incidentType ||
        item.incident_type ||
        item.classification ||
        "Security Incident",

      severity: item.severity || "Low",
      priority: item.priority || "P4",
      status: item.status || item.state || "Open",

      classification:
        item.classification ||
        item.incidentType ||
        item.incident_type ||
        item.tier ||
        "Incident",

      riskScore,

      confidence: formatConfidence(item.aiConfidence ?? item.confidence ?? 0),
      aiConfidence: item.aiConfidence ?? item.confidence ?? 0,

      reasoning:
        item.reasoning ||
        item.aiReasoning ||
        item.ai_reasoning ||
        item.lastReason ||
        item.last_reason ||
        "No reasoning available.",

      recommended_action:
        item.recommendedAction ||
        item.recommended_action ||
        "-",

      recommendedAction:
        item.recommendedAction ||
        item.recommended_action ||
        "-",

      threat_intel: threatIntel,
      threatIntel,

      historical_matches:
        item.historicalMatches ||
        item.historical_matches ||
        0,

      process: item.process || item.processName || item.process_name || "-",
      username: item.username || item.user || "-",
      agent: item.host || item.agent || item.agentName || item.agent_name || "-",
      ip: item.ip || item.agentIp || item.agent_ip || "-",

      source: item.source || "wazuh",
      tenant_id: item.tenant_id || item.tenantId || "tenant_1",

      escalationStatus: item.escalationStatus || item.escalation_status || "pending",

      requiresHumanReview:
        normalizeStatus(item.status) === "investigating" ||
        String(item.classification || item.incidentType || "")
          .toLowerCase()
          .includes("investigation"),

      suppressionCandidate: Boolean(item.suppressionCandidate || item.suppression_candidate),
      autoCloseEligible: Boolean(item.autoCloseEligible || item.auto_close_eligible),

      lastSeen: item.lastSeen || item.last_seen || item.updatedAt || item.createdAt || "-",
      createdAt: item.createdAt || "-",
      updatedAt: item.updatedAt || "-",

      indicators: toArray(item.indicators || item.iocs || item.IOCs),
      attackChain: toArray(item.attackChain || item.attack_chain),
      networkConnections: toArray(item.networkConnections || item.network_connections),
      mitreTechniques: toArray(item.mitreTechniques || item.mitre || item.mitre_techniques),

      evidence,
      relatedAlerts,
      timeline,
      playbooks,

      relatedAlertCount: item.relatedAlertCount || relatedAlerts.length || 0,
      evidenceCount: item.evidenceCount || evidence.length || 0,
      timelineCount: item.timelineCount || timeline.length || 0,
      playbookCount: item.playbookCount || playbooks.length || 0,
    };
  };

  const loadIncidents = async () => {
    try {
      setLoading(true);
      setError("");

      const res = await fetch(`${API_BASE}/api/incidents?limit=5`, {
        method: "GET",
        headers: {
          Accept: "application/json",
        },
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        console.error("Incidents API failed:", data);
        setError(`Incidents API failed: ${res.status}`);
        setIncidents([]);
        setSelectedIncident(null);
        return;
      }

      const cleanData = getPayloadArray(data)
        .map(normalizeIncident)
        .filter((incident) => incident.incidentKey);

      cleanData.sort((a, b) => {
        const riskDiff = safeNumber(b.riskScore) - safeNumber(a.riskScore);
        if (riskDiff !== 0) return riskDiff;

        return (
          new Date(b.lastSeen || b.updatedAt || b.createdAt || 0) -
          new Date(a.lastSeen || a.updatedAt || a.createdAt || 0)
        );
      });

      setIncidents(cleanData);
      setLastUpdated(new Date());

      setSelectedIncident((prev) => {
        if (cleanData.length === 0) return null;
        if (!prev) return cleanData[0];

        return (
          cleanData.find((item) => item.incidentKey === prev.incidentKey) ||
          cleanData[0]
        );
      });
    } catch (err) {
      console.error("Incidents fetch error:", err);
      setError("Frontend cannot reach backend incidents API.");
      setIncidents([]);
      setSelectedIncident(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();

    const interval = setInterval(() => {
      loadIncidents();
    }, 60000);

    return () => clearInterval(interval);
  }, []);

  const handleDecision = async (incident, decision) => {
    try {
      setDecisionLoading(true);

      const alertId = getEvidenceAlertId(incident);

      if (!alertId) {
        alert("No related alert ID found for this incident.");
        return;
      }

      const res = await fetch(`${API_BASE}/api/wazuh/analyst-decision`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          alert_id: alertId,
          tenant_id: incident.tenant_id || "tenant_1",
          decision,
          analyst: "shruthi",
          reason:
            decision === "false_positive"
              ? "Known admin/system activity"
              : decision === "true_positive"
              ? "Confirmed security issue"
              : "Needs further investigation",
          incidentKey: incident.incidentKey,
        }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        console.error("Decision save failed:", data);
        alert("Decision save failed. Check backend console.");
        return;
      }

      await loadIncidents();

      alert(
        decision === "false_positive"
          ? "False positive learning updated."
          : decision === "true_positive"
          ? "Security escalation updated."
          : "Investigation incident updated."
      );
    } catch (err) {
      console.error("Decision save failed:", err);
      alert("Decision save failed. Backend not reachable.");
    } finally {
      setDecisionLoading(false);
    }
  };

  const openCount = incidents.filter(
    (item) => normalizeStatus(item.status) === "open"
  ).length;

  const investigatingCount = incidents.filter(
    (item) => normalizeStatus(item.status) === "investigating"
  ).length;

  const resolvedCount = incidents.filter(
    (item) => normalizeStatus(item.status) === "resolved"
  ).length;

  const criticalCount = incidents.filter(
    (item) =>
      String(item.severity).toLowerCase() === "critical" ||
      safeNumber(item.riskScore) >= 80
  ).length;

  const highCount = incidents.filter(
    (item) =>
      String(item.severity).toLowerCase() === "high" ||
      safeNumber(item.riskScore) >= 60
  ).length;

  const reviewCount = incidents.filter(
    (item) =>
      item.requiresHumanReview ||
      normalizeStatus(item.status) === "investigating" ||
      String(item.classification || "").toLowerCase().includes("investigation")
  ).length;

  const tabs = [
    {
      name: "All",
      label: `All (${incidents.length})`,
    },
    {
      name: "Open",
      label: `Open (${openCount})`,
    },
    {
      name: "Investigating",
      label: `Investigating (${investigatingCount})`,
    },
    {
      name: "Resolved",
      label: `Resolved (${resolvedCount})`,
    },
  ];

  const detailTabs = [
    "Overview",
    "Evidence",
    "Timeline",
    "MITRE",
    "Playbooks",
    "Raw",
  ];

  const filteredIncidents = useMemo(() => {
    let results = incidents.filter((item) => {
      const status = normalizeStatus(item.status);

      if (activeTab === "Open") return status === "open";
      if (activeTab === "Investigating") return status === "investigating";
      if (activeTab === "Resolved") return status === "resolved";

      return true;
    });

    if (!search.trim()) return results;

    const q = search.toLowerCase();

    return results.filter((item) => {
      return [
        item.title,
        item.incidentKey,
        item.severity,
        item.priority,
        item.status,
        item.agent,
        item.ip,
        item.username,
        item.process,
        item.classification,
        item.reasoning,
        item.recommended_action,
        item.threat_intel,
        item.source,
        ...item.mitreTechniques.map(normalizeListValue),
        ...item.indicators.map(normalizeListValue),
      ]
        .join(" ")
        .toLowerCase()
        .includes(q);
    });
  }, [incidents, activeTab, search]);

  return (
    <SiemLayout>
      <div className="incidents-page">
        <div className="incidents-header">
          <div>
            <p className="incidents-kicker">Incident Response</p>
            <h1>Real Security Incidents</h1>
            <span>
              Dynamic incidents created from Wazuh alerts, Claude triage,
              analyst decisions, correlation, evidence, playbooks, and AI risk
              scoring.
            </span>
          </div>

          <div className="incidents-header-meta">
            <strong>{loading ? "Syncing..." : error ? "API Error" : "Live"}</strong>
            <small>
              Last updated:{" "}
              {lastUpdated
                ? lastUpdated.toLocaleTimeString("en-GB", {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit",
                  })
                : "-"}
            </small>
            <button onClick={loadIncidents} disabled={loading}>
              Refresh
            </button>
          </div>
        </div>

        {error && <div className="empty-panel">{error}</div>}

        <div className="incident-stats-grid">
          <div className="incident-stat-card">
            <h2>{loading ? "..." : incidents.length}</h2>
            <p>Total Incidents</p>
          </div>

          <div className="incident-stat-card red">
            <h2>{loading ? "..." : criticalCount}</h2>
            <p>Critical</p>
          </div>

          <div className="incident-stat-card orange">
            <h2>{loading ? "..." : highCount}</h2>
            <p>High / Elevated</p>
          </div>

          <div className="incident-stat-card yellow">
            <h2>{loading ? "..." : reviewCount}</h2>
            <p>Human Review</p>
          </div>
        </div>

        <div className="incident-toolbar">
          <div className="incident-tabs">
            {tabs.map((tab) => (
              <button
                key={tab.name}
                className={activeTab === tab.name ? "active" : ""}
                onClick={() => setActiveTab(tab.name)}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <input
            type="text"
            placeholder="Search incidents, users, IPs, processes, MITRE..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="incident-search"
          />
        </div>

        <div className="incidents-layout">
          <div className="incident-list">
            {loading ? (
              <div className="empty-panel">Loading incidents...</div>
            ) : filteredIncidents.length === 0 ? (
              <div className="empty-panel">
                No incidents found for this tab/search.
              </div>
            ) : (
              filteredIncidents.map((item) => (
                <div
                  key={item.incidentKey}
                  className={`incident-card ${
                    selectedIncident?.incidentKey === item.incidentKey
                      ? "selected"
                      : ""
                  }`}
                  onClick={() => {
                    setSelectedIncident(item);
                    setDetailTab("Overview");
                  }}
                >
                  <div className="incident-card-top">
                    <span className={`sev ${String(item.severity).toLowerCase()}`}>
                      {item.severity}
                    </span>

                    <span className="risk-pill">Risk {item.riskScore}</span>
                  </div>

                  <h3>{item.title}</h3>

                  <p className="reason-preview">
                    <b>Reason:</b> {item.reasoning}
                  </p>

                  <div className="incident-meta">
                    <span>Agent: {item.agent}</span>
                    <span>IP: {item.ip}</span>
                    <span>User: {item.username}</span>
                    <span>Process: {item.process}</span>
                    <span>Confidence: {item.confidence}</span>
                    <span>Threat Intel: {item.threat_intel}</span>
                    <span>Related Alerts: {item.relatedAlertCount}</span>
                    <span>Evidence: {item.evidenceCount}</span>
                    <span>Timeline: {item.timelineCount}</span>
                    <span>Playbooks: {item.playbookCount}</span>
                    <span>Last Seen: {formatDateTime(item.lastSeen)}</span>
                  </div>
                </div>
              ))
            )}
          </div>

          {selectedIncident ? (
            <aside className="incident-drawer">
              <div className="drawer-header">
                <div>
                  <span
                    className={`sev ${String(
                      selectedIncident.severity
                    ).toLowerCase()}`}
                  >
                    {selectedIncident.severity}
                  </span>
                  <span className="risk-pill">
                    Risk {selectedIncident.riskScore}
                  </span>
                </div>

                <button onClick={() => setSelectedIncident(null)}>×</button>
              </div>

              <h2>{selectedIncident.title}</h2>

              <p className="incident-key">{selectedIncident.incidentKey}</p>

              <div className="incident-detail-tabs">
                {detailTabs.map((tab) => (
                  <button
                    key={tab}
                    className={detailTab === tab ? "active" : ""}
                    onClick={() => setDetailTab(tab)}
                  >
                    {tab}
                  </button>
                ))}
              </div>

              {detailTab === "Overview" && (
                <>
                  <div className="drawer-grid">
                    <div className="drawer-card">
                      <small>PRIORITY</small>
                      <b>{selectedIncident.priority}</b>
                    </div>

                    <div className="drawer-card">
                      <small>RISK SCORE</small>
                      <b>{selectedIncident.riskScore}</b>
                    </div>

                    <div className="drawer-card">
                      <small>CONFIDENCE</small>
                      <b>{selectedIncident.confidence}</b>
                    </div>

                    <div className="drawer-card">
                      <small>STATUS</small>
                      <b>{selectedIncident.status}</b>
                    </div>

                    <div className="drawer-card">
                      <small>AGENT</small>
                      <span>{selectedIncident.agent}</span>
                    </div>

                    <div className="drawer-card">
                      <small>IP</small>
                      <span>{selectedIncident.ip}</span>
                    </div>

                    <div className="drawer-card">
                      <small>USERNAME</small>
                      <span>{selectedIncident.username}</span>
                    </div>

                    <div className="drawer-card">
                      <small>PROCESS</small>
                      <span>{selectedIncident.process}</span>
                    </div>

                    <div className="drawer-card">
                      <small>INCIDENT TYPE</small>
                      <span>{selectedIncident.classification}</span>
                    </div>

                    <div className="drawer-card">
                      <small>ESCALATION</small>
                      <span>{selectedIncident.escalationStatus}</span>
                    </div>

                    <div className="drawer-card">
                      <small>HUMAN REVIEW</small>
                      <span>
                        {selectedIncident.requiresHumanReview ? "YES" : "NO"}
                      </span>
                    </div>

                    <div className="drawer-card">
                      <small>AUTO CLOSE</small>
                      <span>
                        {selectedIncident.autoCloseEligible ? "YES" : "NO"}
                      </span>
                    </div>

                    <div className="drawer-card">
                      <small>SUPPRESSION</small>
                      <span>
                        {selectedIncident.suppressionCandidate ? "YES" : "NO"}
                      </span>
                    </div>

                    <div className="drawer-card">
                      <small>SOURCE</small>
                      <span>{selectedIncident.source}</span>
                    </div>

                    <div className="drawer-card">
                      <small>LAST SEEN</small>
                      <span>{formatDateTime(selectedIncident.lastSeen)}</span>
                    </div>

                    <div className="drawer-card">
                      <small>HISTORICAL MATCHES</small>
                      <span>{selectedIncident.historical_matches}</span>
                    </div>
                  </div>

                  <div className="drawer-card wide-card">
                    <small>DETAILED REASONING</small>
                    <p>{selectedIncident.reasoning}</p>
                  </div>

                  <div className="drawer-card wide-card">
                    <small>RECOMMENDED ACTION</small>
                    <p>{selectedIncident.recommended_action}</p>
                  </div>

                  <div className="drawer-card wide-card">
                    <small>THREAT INTEL</small>
                    <p>{selectedIncident.threat_intel}</p>
                  </div>
                </>
              )}

              {detailTab === "Evidence" && (
                <>
                  <div className="drawer-card wide-card">
                    <small>EVIDENCE SUMMARY</small>
                    <p>Evidence records: {selectedIncident.evidenceCount}</p>
                    <p>Related alerts: {selectedIncident.relatedAlertCount}</p>
                  </div>

                  <div className="drawer-card wide-card">
                    <small>INDICATORS / IOCS</small>

                    {selectedIncident.indicators.length === 0 ? (
                      <p>No indicators found.</p>
                    ) : (
                      selectedIncident.indicators.map((indicator, index) => (
                        <p key={`indicator-${index}`}>
                          {normalizeListValue(indicator)}
                        </p>
                      ))
                    )}
                  </div>

                  <div className="drawer-card wide-card">
                    <small>NETWORK CONNECTIONS</small>

                    {selectedIncident.networkConnections.length === 0 ? (
                      <p>No network data.</p>
                    ) : (
                      selectedIncident.networkConnections.map((item, index) => (
                        <p key={`network-${index}`}>
                          {normalizeListValue(item)}
                        </p>
                      ))
                    )}
                  </div>

                  <div className="drawer-card wide-card">
                    <small>ATTACK CHAIN</small>

                    {selectedIncident.attackChain.length === 0 ? (
                      <p>No attack chain built yet.</p>
                    ) : (
                      selectedIncident.attackChain.map((item, index) => (
                        <p key={`attack-chain-${index}`}>
                          {normalizeListValue(item)}
                        </p>
                      ))
                    )}
                  </div>

                  <div className="drawer-card wide-card">
                    <small>RELATED ALERTS</small>

                    {selectedIncident.relatedAlerts.length === 0 ? (
                      <p>Backend returned {selectedIncident.relatedAlertCount} related alerts.</p>
                    ) : (
                      selectedIncident.relatedAlerts.map((alert, index) => (
                        <p key={`related-alert-${index}`}>
                          <b>
                            {alert.rule_description ||
                              alert.ruleDescription ||
                              alert.rule?.description ||
                              alert.title ||
                              alert._id ||
                              "Alert"}
                          </b>{" "}
                          <small>
                            {alert.verdict || alert.status || "-"} | Risk{" "}
                            {alert.risk || alert.riskScore || "-"}
                          </small>
                        </p>
                      ))
                    )}
                  </div>
                </>
              )}

              {detailTab === "Timeline" && (
                <div className="drawer-card wide-card">
                  <small>TIMELINE</small>

                  {selectedIncident.timeline.length === 0 ? (
                    <p>Backend returned {selectedIncident.timelineCount} timeline events.</p>
                  ) : (
                    selectedIncident.timeline.map((event, index) => (
                      <div className="timeline-item" key={`timeline-${index}`}>
                        <b>{event.type || event.eventType || "EVENT"}</b>
                        <p>{event.message || event.description || "-"}</p>
                        <small>
                          {formatDateTime(event.time || event.timestamp)}
                          {event.actor ? ` | ${event.actor}` : ""}
                        </small>
                      </div>
                    ))
                  )}
                </div>
              )}

              {detailTab === "MITRE" && (
                <>
                  <div className="drawer-card wide-card">
                    <small>MITRE TECHNIQUES</small>

                    {selectedIncident.mitreTechniques.length === 0 ? (
                      <p>No MITRE mapping found.</p>
                    ) : (
                      selectedIncident.mitreTechniques.map((item, index) => (
                        <p key={`mitre-${index}`}>{normalizeListValue(item)}</p>
                      ))
                    )}
                  </div>

                  <div className="mitre-mini-grid">
                    {selectedIncident.mitreTechniques.length === 0 ? (
                      <div className="mitre-box empty">No ATT&CK data</div>
                    ) : (
                      selectedIncident.mitreTechniques.map((item, index) => (
                        <div className="mitre-box" key={`mitre-box-${index}`}>
                          {normalizeListValue(item)}
                        </div>
                      ))
                    )}
                  </div>
                </>
              )}

              {detailTab === "Playbooks" && (
                <div className="drawer-card wide-card">
                  <small>PLAYBOOKS</small>

                  {selectedIncident.playbooks.length === 0 ? (
                    <p>Backend returned {selectedIncident.playbookCount} playbook actions.</p>
                  ) : (
                    selectedIncident.playbooks.map((playbook, index) => (
                      <div className="playbook-item" key={`playbook-${index}`}>
                        <b>
                          {playbook.title ||
                            playbook.name ||
                            `Playbook Action ${index + 1}`}
                        </b>
                        <p>
                          {playbook.action ||
                            playbook.description ||
                            normalizeListValue(playbook)}
                        </p>
                        <small>{playbook.status || "pending approval"}</small>
                      </div>
                    ))
                  )}
                </div>
              )}

              {detailTab === "Raw" && (
                <div className="drawer-card wide-card">
                  <small>RAW INCIDENT JSON</small>

                  <pre
                    style={{
                      whiteSpace: "pre-wrap",
                      overflow: "auto",
                      maxHeight: "520px",
                      background: "#081a33",
                      padding: "12px",
                      borderRadius: "10px",
                      color: "#d7e7ff",
                      fontSize: "12px",
                    }}
                  >
                    {JSON.stringify(selectedIncident, null, 2)}
                  </pre>
                </div>
              )}

              <div className="human-actions">
                <button
                  disabled={decisionLoading}
                  onClick={() =>
                    handleDecision(selectedIncident, "true_positive")
                  }
                >
                  Confirm TP
                </button>

                <button
                  disabled={decisionLoading}
                  onClick={() =>
                    handleDecision(selectedIncident, "false_positive")
                  }
                >
                  Confirm FP
                </button>

                <button
                  disabled={decisionLoading}
                  onClick={() =>
                    handleDecision(selectedIncident, "needs_investigation")
                  }
                >
                  Needs Investigation
                </button>
              </div>
            </aside>
          ) : (
            <aside className="incident-drawer empty-drawer">
              <div className="empty-panel">Select an incident to view details.</div>
            </aside>
          )}
        </div>
      </div>
    </SiemLayout>
  );
}