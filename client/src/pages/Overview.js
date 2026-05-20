import React, { useEffect, useMemo, useState } from "react";
import SiemLayout from "../components/siem/SiemLayout";
import "../styles/Overview.css";

const API_BASE = "http://10.0.3.83:5000";

export default function Overview() {
  const [summary, setSummary] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [patterns, setPatterns] = useState([]);
  const [mitre, setMitre] = useState([]);
  const [correlation, setCorrelation] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);

  const getPayloadArray = (payload) => {
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.data)) return payload.data;
    if (Array.isArray(payload?.incidents)) return payload.incidents;
    if (Array.isArray(payload?.alerts)) return payload.alerts;
    if (Array.isArray(payload?.patterns)) return payload.patterns;
    if (Array.isArray(payload?.items)) return payload.items;
    if (Array.isArray(payload?.mitre)) return payload.mitre;
    if (Array.isArray(payload?.techniques)) return payload.techniques;
    if (Array.isArray(payload?.correlations)) return payload.correlations;
    return [];
  };

  const safeNumber = (value, fallback = 0) => {
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
  };

  const normalizeStatus = (status) => {
    const value = String(status || "open").toLowerCase();

    if (value.includes("investigating")) return "investigating";
    if (value.includes("under")) return "investigating";
    if (value.includes("review")) return "investigating";
    if (value.includes("resolved")) return "resolved";
    if (value.includes("closed")) return "resolved";
    if (value.includes("false_positive")) return "resolved";

    return "open";
  };

  const getSeverityFromRisk = (risk = 0) => {
    const value = safeNumber(risk);

    if (value >= 80) return "Critical";
    if (value >= 60) return "High";
    if (value >= 30) return "Medium";
    return "Low";
  };

  const formatDateTime = (value) => {
    if (!value || value === "-") return "-";

    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);

    return date.toLocaleString("en-GB", {
      day: "2-digit",
      month: "short",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const normalizeIncident = (item, index) => {
    const evidence = Array.isArray(item.evidence) ? item.evidence : [];
    const firstEvidence = evidence[0] || {};

    const riskScore = safeNumber(
      item.riskScore ||
        item.risk ||
        item.finalRisk ||
        item.aiRisk ||
        firstEvidence.riskScore ||
        firstEvidence.risk,
      0
    );

    return {
      ...item,
      id: item._id || item.id || item.incidentKey || `incident-${index}`,
      incidentKey: item.incidentKey || item._id || `incident-${index}`,
      title: item.title || item.classification || item.incidentType || "Incident",
      riskScore,
      severity: item.severity || firstEvidence.severity || getSeverityFromRisk(riskScore),
      priority: item.priority || "P4",
      status: item.status || "Open",
      normalizedStatus: normalizeStatus(item.status),
      host: item.host || item.agent || firstEvidence.agent || "-",
      user: item.users?.[0] || item.username || firstEvidence.username || "-",
      process: item.processes?.[0] || item.process || firstEvidence.process || "-",
      classification:
        item.classification || item.incidentType || item.tier || "Incident",
      reasoning:
        firstEvidence.reasoning ||
        item.reasoning ||
        item.notes?.[0]?.note ||
        "No reasoning available.",
      lastSeen: item.lastSeen || item.updatedAt || item.createdAt || "-",
    };
  };

  const normalizeAlert = (item, index) => {
    const rawAlert = item.rawAlert || item.raw?.rawAlert || item.raw || {};
    const risk = safeNumber(
      item.risk ??
        item.riskScore ??
        item.risk_score ??
        item.ruleLevel ??
        item.rule_level ??
        item.rule?.level ??
        rawAlert.rule?.level ??
        0
    );

    return {
      ...item,
      id: item._id || item.id || item.alert_id || item.alertId || `alert-${index}`,
      title:
        item.rule_description ||
        item.ruleDescription ||
        item.rule?.description ||
        rawAlert.rule?.description ||
        "Wazuh Alert",
      risk,
      severity: getSeverityFromRisk(risk),
      verdict: item.verdict || item.status || "pending",
      confidence: item.confidence ?? item.aiConfidence ?? "-",
      agent:
        item.agent?.name ||
        item.agent ||
        item.agentName ||
        rawAlert.agent?.name ||
        "unknown-agent",
      timestamp: item.timestamp || item.createdAt || rawAlert.timestamp || "-",
    };
  };

  const loadOverview = async () => {
    try {
      setLoading(true);

      const [
        summaryRes,
        incidentsRes,
        alertsRes,
        patternsRes,
        mitreRes,
        correlationRes,
      ] = await Promise.allSettled([
        fetch(`${API_BASE}/api/wazuh/summary`),
        fetch(`${API_BASE}/api/incidents?limit=100`),
        fetch(`${API_BASE}/api/wazuh/analyst-queue?limit=500`),
        fetch(`${API_BASE}/api/wazuh/alert-patterns`),
        fetch(`${API_BASE}/api/wazuh/mitre-lite`),
        fetch(`${API_BASE}/api/wazuh/correlation-lite`),
      ]);

      const readJson = async (result) => {
        if (result.status !== "fulfilled") return null;

        try {
          return await result.value.json();
        } catch {
          return null;
        }
      };

      const [
        summaryData,
        incidentsData,
        alertsData,
        patternsData,
        mitreData,
        correlationData,
      ] = await Promise.all([
        readJson(summaryRes),
        readJson(incidentsRes),
        readJson(alertsRes),
        readJson(patternsRes),
        readJson(mitreRes),
        readJson(correlationRes),
      ]);

      const cleanIncidents = getPayloadArray(incidentsData)
        .map(normalizeIncident)
        .sort((a, b) => {
          const riskDiff = safeNumber(b.riskScore) - safeNumber(a.riskScore);
          if (riskDiff !== 0) return riskDiff;
          return new Date(b.lastSeen || 0) - new Date(a.lastSeen || 0);
        });

      const cleanAlerts = getPayloadArray(alertsData)
        .map(normalizeAlert)
        .sort((a, b) => safeNumber(b.risk) - safeNumber(a.risk));

      setSummary(summaryData || null);
      setIncidents(cleanIncidents);
      setAlerts(cleanAlerts);
      setPatterns(getPayloadArray(patternsData));
      setMitre(getPayloadArray(mitreData));
      setCorrelation(getPayloadArray(correlationData));
      setLastUpdated(new Date());
    } catch (err) {
      console.error("Overview fetch error:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadOverview();

    const interval = setInterval(loadOverview, 60000);

    return () => clearInterval(interval);
  }, []);

  const stats = useMemo(() => {
    const totalAgents = safeNumber(
  summary?.totalAgents ||
  summary?.agents?.total ||
  summary?.agents?.count ||
  summary?.agentSummary?.total ||
  new Set(alerts.map((a) => a.agent).filter(Boolean)).size
);

const activeAgents = safeNumber(
  summary?.activeAgents ||
  summary?.agents?.active ||
  summary?.agentSummary?.active ||
  new Set(alerts.map((a) => a.agent).filter(Boolean)).size
);

const disconnectedAgents = safeNumber(
  summary?.disconnectedAgents ||
  summary?.agents?.disconnected ||
  summary?.agentSummary?.disconnected
);

const neverConnectedAgents = safeNumber(
  summary?.neverConnectedAgents ||
  summary?.agents?.neverConnected ||
  summary?.agentSummary?.neverConnected
);

    const activePercent =
      totalAgents > 0 ? Math.round((activeAgents / totalAgents) * 100) : 0;

    const openIncidents = incidents.filter(
      (item) => item.normalizedStatus === "open"
    ).length;

    const investigatingIncidents = incidents.filter(
      (item) => item.normalizedStatus === "investigating"
    ).length;

    const resolvedIncidents = incidents.filter(
      (item) => item.normalizedStatus === "resolved"
    ).length;

    const criticalIncidents = incidents.filter(
      (item) => String(item.severity).toLowerCase() === "critical"
    ).length;

    const highIncidents = incidents.filter(
      (item) => String(item.severity).toLowerCase() === "high"
    ).length;

    const pendingAlerts = alerts.filter((item) => {
      const verdict = String(item.verdict || "").toLowerCase();
      return verdict === "pending" || verdict === "unknown" || verdict === "open";
    }).length;

    const falsePositive = alerts.filter(
      (item) => String(item.verdict || "").toLowerCase() === "false_positive"
    ).length;

    const truePositive = alerts.filter(
      (item) => String(item.verdict || "").toLowerCase() === "true_positive"
    ).length;

    const needsInvestigation = alerts.filter((item) => {
      const verdict = String(item.verdict || "").toLowerCase();
      return verdict === "needs_investigation" || verdict === "needs_review";
    }).length;

    const noisyPatterns = patterns.filter(
      (item) =>
        item.suppression_candidate ||
        item.suppressionCandidate ||
        safeNumber(item.fp_rate || item.fpRate) >= 0.8
    ).length;

    const dangerousPatterns = patterns.filter(
      (item) =>
        item.dangerous_pattern ||
        item.dangerousPattern ||
        safeNumber(item.tp_count || item.tpCount) > 0
    ).length;

    const avgRisk =
      incidents.length === 0
        ? 0
        : Math.round(
            incidents.reduce((sum, item) => sum + safeNumber(item.riskScore), 0) /
              incidents.length
          );

    return {
      totalAgents,
      activeAgents,
      disconnectedAgents,
      neverConnectedAgents,
      activePercent,
      openIncidents,
      investigatingIncidents,
      resolvedIncidents,
      criticalIncidents,
      highIncidents,
      pendingAlerts,
      falsePositive,
      truePositive,
      needsInvestigation,
      noisyPatterns,
      dangerousPatterns,
      avgRisk,
    };
  }, [summary, incidents, alerts, patterns]);

  const overviewCards = [
    {
      title: "TOTAL AGENTS",
      value: stats.totalAgents,
      color: "blue",
    },
    {
      title: "ACTIVE AGENTS",
      value: stats.activeAgents,
      color: "green",
      sub: `${stats.activePercent}% active`,
    },
    {
      title: "DISCONNECTED",
      value: stats.disconnectedAgents,
      color: "red",
    },
    {
      title: "OPEN INCIDENTS",
      value: stats.openIncidents,
      color: "blue",
    },
    {
      title: "CRITICAL",
      value: stats.criticalIncidents,
      color: "red",
    },
    {
      title: "HIGH",
      value: stats.highIncidents,
      color: "orange",
    },
    {
      title: "PENDING TRIAGE",
      value: stats.pendingAlerts,
      color: "yellow",
    },
    {
      title: "AVG RISK",
      value: stats.avgRisk,
      color: "purple",
    },
    {
      title: "WAZUH VERSION",
      value: summary?.manager?.version || "-",
      color: "purple",
    },
  ];

  const latestIncidents = incidents.slice(0, 6);
  const topAlerts = alerts.slice(0, 5);
  const topMitre = mitre.slice(0, 6);
  const topCorrelation = correlation.slice(0, 5);

  return (
    <SiemLayout>
      <div className="overview-content">
        <div className="overview-header">
          <div>
            <p className="overview-kicker">Security Overview</p>
            <h1>Belzir AI-SOC Command Center</h1>
            <span>
              Real-time overview from Wazuh agents, Claude AI triage, incident
              engine, detection learning, MITRE-lite and correlation-lite.
            </span>
          </div>

          <div className="overview-live-card">
            <strong>{loading ? "Syncing..." : "Live"}</strong>
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
          </div>
        </div>

        <div className="cards-grid">
          {overviewCards.map((card) => (
            <div className="overview-card" key={card.title}>
              <p>{card.title}</p>
              <h2 className={card.color || ""}>{loading ? "..." : card.value}</h2>
              {card.sub && <span>{card.sub}</span>}
            </div>
          ))}
        </div>

        <div className="overview-main-grid">
          <section className="overview-panel large">
            <div className="overview-panel-header">
              <div>
                <h2>Active Incidents</h2>
                <p>Highest risk incidents created from real alert evidence.</p>
              </div>
              <span>{incidents.length}</span>
            </div>

            {loading ? (
              <div className="overview-empty">Loading incidents...</div>
            ) : latestIncidents.length === 0 ? (
              <div className="overview-empty">No incidents found.</div>
            ) : (
              <div className="overview-list">
                {latestIncidents.map((item) => (
                  <div className="overview-list-item" key={item.incidentKey}>
                    <div>
                      <span className={`sev ${String(item.severity).toLowerCase()}`}>
                        {item.severity}
                      </span>
                      <h3>{item.title}</h3>
                      <p>{item.reasoning}</p>

                      <div className="overview-tags">
                        <span>{item.host}</span>
                        <span>{item.user}</span>
                        <span>{item.process}</span>
                        <span>{formatDateTime(item.lastSeen)}</span>
                      </div>
                    </div>

                    <div className="overview-risk">
                      <b>{item.riskScore}</b>
                      <small>{item.priority}</small>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="overview-panel">
            <div className="overview-panel-header">
              <div>
                <h2>SOC Health</h2>
                <p>Current operational and detection state.</p>
              </div>
            </div>

            <div className="health-grid">
              <div>
                <small>Investigating</small>
                <strong>{stats.investigatingIncidents}</strong>
              </div>
              <div>
                <small>Resolved</small>
                <strong>{stats.resolvedIncidents}</strong>
              </div>
              <div>
                <small>Noisy Rules</small>
                <strong>{stats.noisyPatterns}</strong>
              </div>
              <div>
                <small>Dangerous</small>
                <strong>{stats.dangerousPatterns}</strong>
              </div>
            </div>

            <div className="health-meter">
              <div>
                <span>Agent Coverage</span>
                <b>{stats.activePercent}%</b>
              </div>
              <div className="meter-line">
                <div style={{ width: `${Math.min(stats.activePercent, 100)}%` }} />
              </div>
            </div>

            <div className="summary-box">
              <small>Manager</small>
              <p>{summary?.manager?.name || "-"}</p>
              <small>Never Connected</small>
              <p>{stats.neverConnectedAgents}</p>
            </div>
          </section>

          <section className="overview-panel">
            <div className="overview-panel-header">
              <div>
                <h2>AI Triage Verdicts</h2>
                <p>Analyst queue distribution.</p>
              </div>
            </div>

            <div className="verdict-grid">
              <div>
                <small>Pending</small>
                <strong>{stats.pendingAlerts}</strong>
              </div>
              <div>
                <small>True Positive</small>
                <strong>{stats.truePositive}</strong>
              </div>
              <div>
                <small>False Positive</small>
                <strong>{stats.falsePositive}</strong>
              </div>
              <div>
                <small>Investigation</small>
                <strong>{stats.needsInvestigation}</strong>
              </div>
            </div>
          </section>

          <section className="overview-panel">
            <div className="overview-panel-header">
              <div>
                <h2>Top Triage Alerts</h2>
                <p>Highest risk analyst queue items.</p>
              </div>
              <span>{alerts.length}</span>
            </div>

            {topAlerts.length === 0 ? (
              <div className="overview-empty">No alerts found.</div>
            ) : (
              <div className="compact-list">
                {topAlerts.map((item) => (
                  <div className="compact-item" key={item.id}>
                    <div>
                      <h4>{item.title}</h4>
                      <p>
                        {item.agent} | {item.verdict} | Risk {item.risk}
                      </p>
                    </div>
                    <span className={`sev ${String(item.severity).toLowerCase()}`}>
                      {item.risk}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="overview-panel">
            <div className="overview-panel-header">
              <div>
                <h2>MITRE-lite</h2>
                <p>Observed techniques from alert enrichment.</p>
              </div>
              <span>{mitre.length}</span>
            </div>

            {topMitre.length === 0 ? (
              <div className="overview-empty">No MITRE data found.</div>
            ) : (
              <div className="mitre-overview-grid">
                {topMitre.map((item, index) => (
                  <div className="mitre-overview-box" key={item.id || index}>
                    {item.technique ||
                      item.techniqueId ||
                      item.name ||
                      item.title ||
                      JSON.stringify(item)}
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="overview-panel">
            <div className="overview-panel-header">
              <div>
                <h2>Correlation-lite</h2>
                <p>Related alert groups and repeated behavior.</p>
              </div>
              <span>{correlation.length}</span>
            </div>

            {topCorrelation.length === 0 ? (
              <div className="overview-empty">No correlation data found.</div>
            ) : (
              <div className="compact-list">
                {topCorrelation.map((item, index) => (
                  <div className="compact-item" key={item.id || index}>
                    <div>
                      <h4>
                        {item.title ||
                          item.rule ||
                          item.ruleDescription ||
                          item.rule_description ||
                          "Correlation Group"}
                      </h4>
                      <p>
                        {item.agent || item.host || "-"} | Count{" "}
                        {item.count || item.alertCount || item.total || "-"}
                      </p>
                    </div>
                    <span>{item.risk || item.riskScore || "-"}</span>
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
      </div>
    </SiemLayout>
  );
}