import React, { useEffect, useMemo, useState } from "react";
import SiemLayout from "../components/siem/SiemLayout";
import "../styles/DailyReview.css";

const API_BASE = "http://10.0.3.83:5000";

export default function DailyReview() {
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [patterns, setPatterns] = useState([]);
  const [loading, setLoading] = useState(true);

  const normalizeStatus = (status) => {
    const value = (status || "open").toLowerCase();
    if (value === "under investigation") return "investigating";
    if (value === "closed") return "resolved";
    return value;
  };

  const normalizeVerdict = (verdict) => {
    if (verdict === "true_positive") return "TP";
    if (verdict === "false_positive") return "FP";
    if (verdict === "needs_investigation" || verdict === "needs_review")
      return "Investigate";
    return "Pending";
  };

  const getPayloadArray = (payload) => {
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.data)) return payload.data;
    if (Array.isArray(payload?.incidents)) return payload.incidents;
    return [];
  };

  const getDate = (item) => {
    const value =
      item.timestamp ||
      item.createdAt ||
      item.updatedAt ||
      item.lastSeen ||
      item.rawAlert?.timestamp ||
      item.raw?.timestamp;

    const date = value ? new Date(value) : null;
    return date && !Number.isNaN(date.getTime()) ? date : null;
  };

  useEffect(() => {
    async function loadDailyReview() {
      try {
        setLoading(true);

        const [alertsRes, incidentsRes, patternsRes] = await Promise.all([
          fetch(`${API_BASE}/api/wazuh/analyst-queue?limit=500`),
          fetch(`${API_BASE}/api/incidents?limit=100`),
          fetch(`${API_BASE}/api/wazuh/alert-patterns`),
        ]);

        const [alertsData, incidentsData, patternsData] = await Promise.all([
          alertsRes.json(),
          incidentsRes.json(),
          patternsRes.json(),
        ]);

        setAlerts(getPayloadArray(alertsData));
        setPatterns(getPayloadArray(patternsData));
        setIncidents(getPayloadArray(incidentsData));
        
      } catch (err) {
        console.error("Daily Review fetch error:", err);
      } finally {
        setLoading(false);
      }
    }

    loadDailyReview();

    const interval = setInterval(loadDailyReview, 60000);
    return () => clearInterval(interval);
  }, []);

  const last24hAlerts = useMemo(() => {
    const now = Date.now();
    return alerts.filter((item) => {
      const date = getDate(item);
      if (!date) return false;
      const diffHours = (now - date.getTime()) / (1000 * 60 * 60);
      return diffHours >= 0 && diffHours <= 24;
    });
  }, [alerts]);

  const last24hIncidents = useMemo(() => {
    const now = Date.now();
    return incidents.filter((item) => {
      const date = getDate(item);
      if (!date) return false;
      const diffHours = (now - date.getTime()) / (1000 * 60 * 60);
      return diffHours >= 0 && diffHours <= 24;
    });
  }, [incidents]);

  const tpAlerts = last24hAlerts.filter(
    (item) => item.verdict === "true_positive"
  );

  const fpAlerts = last24hAlerts.filter(
    (item) => item.verdict === "false_positive"
  );

  const investigationAlerts = last24hAlerts.filter(
    (item) =>
      item.verdict === "needs_investigation" || item.verdict === "needs_review"
  );

  const highRiskIncidents = incidents.filter(
    (item) => Number(item.riskScore || item.risk || 0) >= 60
  );

  const openIncidents = incidents.filter(
    (item) => normalizeStatus(item.status) === "open"
  );

  const investigatingIncidents = incidents.filter(
    (item) => normalizeStatus(item.status) === "investigating"
  );

  const noisyPatterns = patterns
    .filter(
      (item) =>
        Number(item.fp_rate || 0) >= 0.8 ||
        item.suppression_candidate === true ||
        item.auto_close_eligible === true
    )
    .sort((a, b) => Number(b.fp_rate || 0) - Number(a.fp_rate || 0));

  const stats = [
    { value: last24hAlerts.length, label: "Alerts 24h" },
    { value: tpAlerts.length, label: "True Positive", color: "red" },
    { value: fpAlerts.length, label: "False Positive", color: "blue" },
    {
      value: investigationAlerts.length,
      label: "Needs Investigation",
      color: "yellow",
    },
    { value: highRiskIncidents.length, label: "High Risk", color: "red" },
  ];

  const reviewItems = [
    ...highRiskIncidents.map((item) => ({
      id: item._id || item.incidentKey,
      type: "Incident",
      severity: item.severity || "Medium",
      score: item.riskScore || 0,
      title: item.title || item.classification || "Incident",
      host: item.host || "-",
      time: item.lastSeen || item.updatedAt || item.createdAt || "-",
      action: item.recommendedAction || "Review incident evidence.",
    })),
    ...investigatingIncidents.map((item) => ({
      id: item._id || item.incidentKey,
      type: "Investigation",
      severity: item.severity || "Medium",
      score: item.riskScore || 0,
      title: item.title || "Investigation Incident",
      host: item.host || "-",
      time: item.lastSeen || item.updatedAt || item.createdAt || "-",
      action: item.recommendedAction || "Continue investigation.",
    })),
    ...noisyPatterns.slice(0, 5).map((item) => ({
      id: item._id || item.pattern_key,
      type: "Pattern",
      severity: item.suppression_candidate ? "Medium" : "Low",
      score: Math.round(Number(item.fp_rate || 0) * 100),
      title: item.rule_description || item.pattern_key,
      host: item.agent || "-",
      time: item.updatedAt || item.last_seen || "-",
      action: item.suppression_candidate
        ? "Review suppression candidate."
        : "Monitor noisy pattern.",
    })),
  ]
    .filter(
      (item, index, self) => index === self.findIndex((i) => i.id === item.id)
    )
    .slice(0, 12);

  const criticalHosts = highRiskIncidents
    .map((item) => item.host)
    .filter(Boolean)
    .slice(0, 5)
    .join(", ");

  return (
    <SiemLayout>
      <section className="siem-content">
        <div className="critical-banner">
          <span>●</span>
          {highRiskIncidents.length > 0
            ? `HIGH RISK: Review required for ${
                criticalHosts || "affected hosts"
              }`
            : "SYSTEM NORMAL: No high-risk security incidents detected"}
        </div>

        <div className="stats-grid">
          {stats.map((item) => (
            <div className={`stat-card ${item.color || ""}`} key={item.label}>
              <h2>{loading ? "..." : item.value}</h2>
              <p>{item.label}</p>
            </div>
          ))}
        </div>

        <div className="review-header">
          <h3>NEEDS YOUR REVIEW</h3>
          <button>
            {openIncidents.length + investigatingIncidents.length} Active Cases
          </button>
        </div>

        <div className="review-list">
          {loading ? (
            <div className="review-row">
              <div className="review-left">
                <strong>Loading real SOC daily review...</strong>
              </div>
              <div className="review-right">
                <span>MongoDB</span>
                <span>Live</span>
              </div>
            </div>
          ) : reviewItems.length > 0 ? (
            reviewItems.map((item) => (
              <div className="review-row" key={item.id}>
                <div className="review-left">
                  <span className={`badge ${item.severity.toLowerCase()}`}>
                    {item.severity}
                  </span>

                  <span className="count-badge">{item.score}</span>

                  <strong>{item.title}</strong>
                </div>

                <div className="review-right">
                  <span>{normalizeVerdict(item.type)}</span>
                  <span>{item.host}</span>
                  <span>{item.action}</span>
                  <span className="play">▶</span>
                </div>
              </div>
            ))
          ) : (
            <div className="review-row">
              <div className="review-left">
                <strong>No incidents need review right now</strong>
              </div>

              <div className="review-right">
                <span>Wazuh</span>
                <span>MongoDB</span>
                <span>Claude</span>
              </div>
            </div>
          )}
        </div>
      </section>
    </SiemLayout>
  );
}