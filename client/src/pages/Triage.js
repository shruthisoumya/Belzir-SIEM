import React, { useEffect, useMemo, useState } from "react";
import SiemLayout from "../components/siem/SiemLayout";
import "../styles/Triage.css";

const API_BASE = "http://10.0.3.83:5000";
const CORRELATION_WINDOW_MINUTES = 60;

export default function Triage() {
  const [alerts, setAlerts] = useState([]);
  const [activeTab, setActiveTab] = useState("All");
  const [activeRange, setActiveRange] = useState("3D");
  const [selectedSummary, setSelectedSummary] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [alertDetailsLoading, setAlertDetailsLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  const getAnalystName = () => {
    return (
      localStorage.getItem("analystName") ||
      localStorage.getItem("username") ||
      "analyst"
    );
  };

  const getSeverity = (risk = 0) => {
    const value = Number(risk) || 0;

    if (value >= 80) return "Critical";
    if (value >= 60) return "High";
    if (value >= 30) return "Medium";
    return "Low";
  };

  const formatConfidence = (confidence) => {
    if (confidence === null || confidence === undefined || confidence === "-") {
      return "-";
    }

    const value = Number(confidence);

    if (Number.isNaN(value)) return confidence;

    if (value <= 1) return `${Math.round(value * 100)}%`;

    return `${Math.round(value)}%`;
  };

  const getConfidenceNumber = (confidence) => {
    const value = Number(confidence);

    if (Number.isNaN(value)) return 0;

    if (value <= 1) return Math.round(value * 100);

    return Math.round(value);
  };

  const normalizeVerdictValue = (verdict) => {
    const value = String(verdict || "").toLowerCase();

    if (value === "false_positive" || value === "fp" || value === "false positive") {
      return "false_positive";
    }

    if (value === "true_positive" || value === "tp" || value === "true positive") {
      return "true_positive";
    }

    if (
      value === "needs_investigation" ||
      value === "needs_review" ||
      value === "investigate" ||
      value === "investigation" ||
      value === "needs investigation"
    ) {
      return "needs_investigation";
    }

    return "pending";
  };

  const normalizeDecision = (verdict) => {
    const normalized = normalizeVerdictValue(verdict);

    if (normalized === "false_positive") return "False Positive";
    if (normalized === "true_positive") return "True Positive";
    if (normalized === "needs_investigation") return "Investigate";

    return "Pending";
  };

  const isHumanAnalystDecision = (decision) => {
    const analyst = String(decision?.analyst || "").toLowerCase();
    const provider = String(decision?.ai_provider || "").toLowerCase();
    const model = String(decision?.ai_model || "").toLowerCase();

    if (!decision) return false;

    if (provider === "analyst") return true;
    if (model === "human-feedback") return true;

    return ![
      "system",
      "claude",
      "anthropic",
      "local-noise-gate",
      "noise-gate",
      "fallback",
      "",
    ].includes(analyst);
  };

  const getAlertDate = (alert) => {
    const dateValue =
      alert.timestamp ||
      alert.createdAt ||
      alert.updatedAt ||
      alert.time ||
      alert.raw?.timestamp ||
      alert.raw?.createdAt ||
      alert.rawAlert?.timestamp ||
      alert.rawAlert?.createdAt ||
      alert.raw?.rawAlert?.timestamp ||
      alert.raw?.rawAlert?.createdAt ||
      null;

    if (!dateValue) return null;

    const parsed = new Date(dateValue);

    if (Number.isNaN(parsed.getTime())) {
      console.warn("Invalid alert timestamp:", dateValue, alert);
      return null;
    }

    return parsed;
  };

  const getAlertId = (alert, index) => {
    return (
      alert.alert_id ||
      alert.alertId ||
      alert._id ||
      alert.id ||
      alert.wazuhAlertId ||
      alert.raw?._id ||
      alert.rawAlert?._id ||
      `triage-${index}`
    );
  };

  const mapAlerts = (payload) => {
    const data = Array.isArray(payload)
      ? payload
      : Array.isArray(payload?.data)
      ? payload.data
      : Array.isArray(payload?.alerts)
      ? payload.alerts
      : Array.isArray(payload?.items)
      ? payload.items
      : [];

    return data.map((alert, index) => {
      const rawAlert = alert.rawAlert || alert.raw?.rawAlert || alert.raw || {};
      const analystDecision =
        alert.analyst_decision ||
        alert.analystDecision ||
        alert.decisionRecord ||
        null;

      const risk =
        alert.risk ??
        alert.riskScore ??
        alert.risk_score ??
        alert.rule_level ??
        alert.ruleLevel ??
        alert.rule?.level ??
        rawAlert.rule?.level ??
        0;

      const alertDate = getAlertDate(alert);
      const confidence = alert.confidence ?? alert.aiConfidence ?? "-";

      const aiVerdict =
        alert.ai_verdict ||
        alert.aiVerdict ||
        alert.verdict ||
        analystDecision?.ai_verdict ||
        analystDecision?.raw_response?.verdict ||
        "pending";

      const finalVerdict =
        analystDecision?.decision ||
        alert.verdict ||
        alert.decision ||
        aiVerdict ||
        "pending";

      const analystReviewed = isHumanAnalystDecision(analystDecision);
      const aiDecision = normalizeDecision(aiVerdict);
      const finalDecision = analystReviewed
        ? normalizeDecision(finalVerdict)
        : normalizeDecision(aiVerdict);

      return {
        id: getAlertId(alert, index),
        ruleId:
          alert.rule_id ||
          alert.ruleId ||
          alert.rule?.id ||
          rawAlert.rule?.id ||
          alert.rule_description ||
          alert.ruleDescription ||
          "N/A",
        title:
          alert.rule_description ||
          alert.ruleDescription ||
          alert.rule?.description ||
          rawAlert.rule?.description ||
          alert.title ||
          alert.incident_type ||
          alert.incidentType ||
          "Wazuh Alert",
        level: alert.rule_level || alert.ruleLevel || alert.rule?.level || risk,
        risk,
        severity: getSeverity(risk),
        decision: finalDecision,
        aiDecision,
        analystReviewed,
        verdict: normalizeVerdictValue(finalVerdict),
        aiVerdict: normalizeVerdictValue(aiVerdict),
        confidence,
        confidenceLabel: formatConfidence(confidence),
        confidenceValue: getConfidenceNumber(confidence),
        reasoning:
          alert.reasoning ||
          alert.reason ||
          analystDecision?.reason ||
          analystDecision?.ai_reasoning ||
          "-",
        recommendedAction:
          alert.recommended_action ||
          alert.recommendedAction ||
          analystDecision?.recommended_action ||
          "-",
        historicalMatches:
          alert.historical_matches ??
          alert.historicalMatches ??
          analystDecision?.historical_matches ??
          "-",
        threatIntel:
          alert.threat_intel ||
          alert.threatIntel ||
          analystDecision?.threat_intel ||
          "none",
        incidentType:
          alert.incident_type ||
          alert.incidentType ||
          alert.incident?.incidentType ||
          "-",
        status: alert.status || analystDecision?.status || "open",
        agent:
          alert.agent?.name ||
          alert.agent ||
          alert.agentName ||
          rawAlert.agent?.name ||
          "unknown-agent",
        username:
          alert.username ||
          alert.user ||
          rawAlert.data?.win?.eventdata?.targetUserName ||
          rawAlert.data?.win?.eventdata?.subjectUserName ||
          rawAlert.data?.srcuser ||
          rawAlert.data?.dstuser ||
          "-",
        process:
          alert.process ||
          rawAlert.data?.win?.eventdata?.processName ||
          rawAlert.data?.win?.eventdata?.image ||
          rawAlert.data?.win?.eventdata?.newProcessName ||
          rawAlert.data?.process ||
          rawAlert.process ||
          "-",
        parentApplication:
          alert.parent_application ||
          alert.parentApplication ||
          rawAlert.data?.win?.eventdata?.parentProcessName ||
          "-",
        location: alert.location || rawAlert.location || "-",
        time: alertDate ? alertDate.toLocaleString() : "No timestamp",
        timestamp: alert.timestamp || alert.createdAt || rawAlert.timestamp || "-",
        alertDate,
        raw: alert,
        details: null,
      };
    });
  };

  const normalizeDetailsArray = (value) => {
    if (!value) return [];
    if (Array.isArray(value)) return value;
    if (typeof value === "object") return [value];
    return [];
  };

  const renderValue = (value) => {
    if (value === null || value === undefined || value === "") return "-";
    if (typeof value === "object") return JSON.stringify(value);
    return String(value);
  };

  const openAlertDetails = async (item) => {
    try {
      setSelectedSummary(null);
      setSelectedAlert({
        ...item,
        details: null,
      });
      setAlertDetailsLoading(true);

      const res = await fetch(`${API_BASE}/api/wazuh/alert-details/${item.id}`);
      const data = await res.json();

      if (!res.ok) {
        console.error("Alert details API failed:", data);
        setSelectedAlert({
          ...item,
          details: {
            evidence: [],
            timeline: [],
            playbook: [],
            playbooks: [],
            analyst_decision: null,
            raw: item.raw,
            error: data?.error || data?.message || "Failed to load alert details",
          },
        });
        return;
      }

      setSelectedAlert({
        ...item,
        details: {
          ...data,
          evidence: normalizeDetailsArray(data.evidence),
          timeline: normalizeDetailsArray(data.timeline),
          playbook: normalizeDetailsArray(data.playbook || data.playbooks),
          raw: data.raw || data.rawAlert || item.raw,
        },
      });
    } catch (err) {
      console.error("Alert details fetch failed:", err);
      setSelectedAlert({
        ...item,
        details: {
          evidence: [],
          timeline: [],
          playbook: [],
          playbooks: [],
          analyst_decision: null,
          raw: item.raw,
          error: "Backend not reachable",
        },
      });
    } finally {
      setAlertDetailsLoading(false);
    }
  };

  const loadTriageQueue = async (initial = false) => {
    try {
      if (initial) setLoading(true);

      const res = await fetch(`${API_BASE}/api/wazuh/analyst-queue?limit=500`);
      const data = await res.json();

      if (!res.ok) {
        console.error("Analyst queue API failed:", data);
        return;
      }

      setAlerts(mapAlerts(data));
    } catch (err) {
      console.error("Failed to fetch triage queue:", err);
    } finally {
      if (initial) setLoading(false);
    }
  };

  useEffect(() => {
    loadTriageQueue(true);

    const interval = setInterval(() => {
      loadTriageQueue(false);
    }, 60000);

    return () => clearInterval(interval);
  }, []);

  const rangeFilteredAlerts = useMemo(() => {
    if (activeRange === "ALL") return alerts;

    const rangeHours = {
      "1H": 1,
      "6H": 6,
      "24H": 24,
      "3D": 72,
      "7D": 168,
      "30D": 720,
    };

    const now = new Date();

    return alerts.filter((alert) => {
      if (!alert.alertDate) return false;

      const diffHours =
        (now.getTime() - alert.alertDate.getTime()) / (1000 * 60 * 60);

      return diffHours >= 0 && diffHours <= rangeHours[activeRange];
    });
  }, [alerts, activeRange]);

  const summaryItems = useMemo(() => {
    const grouped = {};

    rangeFilteredAlerts.forEach((item) => {
      if (!item.alertDate) return;

      const bucket = new Date(item.alertDate);
      bucket.setMinutes(0, 0, 0);

      const key = `${item.agent}-${item.ruleId}-${bucket.toISOString()}`;

      if (!grouped[key]) {
        grouped[key] = {
          id: key,
          agent: item.agent,
          ruleId: item.ruleId,
          title: item.title,
          risk: item.risk,
          severity: item.severity,
          confidence: item.confidence,
          confidenceLabel: item.confidenceLabel,
          confidenceValue: item.confidenceValue,
          count: 0,
          hour: bucket.toLocaleString(),
          relatedAlerts: [],
        };
      }

      grouped[key].count += 1;
      grouped[key].risk = Math.max(grouped[key].risk, item.risk);
      grouped[key].confidenceValue = Math.max(
        grouped[key].confidenceValue,
        item.confidenceValue
      );
      grouped[key].confidenceLabel = `${grouped[key].confidenceValue}%`;
      grouped[key].relatedAlerts.push(item);

      const highestRiskAlert = grouped[key].relatedAlerts.reduce(
        (max, current) => (current.risk > max.risk ? current : max)
      );

      grouped[key].severity = highestRiskAlert.severity;
    });

    return Object.values(grouped).sort(
      (a, b) =>
        b.count - a.count ||
        b.risk - a.risk ||
        b.confidenceValue - a.confidenceValue
    );
  }, [rangeFilteredAlerts]);

  const markHumanDecision = async (item, decision) => {
    try {
      const backendDecision =
        decision === "False Positive"
          ? "false_positive"
          : decision === "True Positive"
          ? "true_positive"
          : "needs_investigation";

      const res = await fetch(`${API_BASE}/api/wazuh/analyst-decision`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          alert_id: item.id,
          tenant_id: item.raw?.tenant_id || item.raw?.tenantId || "tenant_1",
          decision: backendDecision,
          analyst: getAnalystName(),
          reason:
            backendDecision === "false_positive"
              ? "Confirmed false positive by analyst"
              : backendDecision === "true_positive"
              ? "Confirmed true positive by analyst"
              : "Marked for deeper investigation",
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        console.error("Decision API failed:", data);
        alert("Decision save failed. Check backend console.");
        return;
      }

      const updatedDecision = normalizeDecision(backendDecision);

      setAlerts((prev) =>
        prev.map((alert) =>
          alert.id === item.id
            ? {
                ...alert,
                decision: updatedDecision,
                verdict: backendDecision,
                analystReviewed: true,
                status:
                  backendDecision === "needs_investigation"
                    ? "under_investigation"
                    : "reviewed",
                raw: {
                  ...alert.raw,
                  verdict: backendDecision,
                  status:
                    backendDecision === "needs_investigation"
                      ? "under_investigation"
                      : "reviewed",
                },
              }
            : alert
        )
      );

      setSelectedAlert((prev) =>
        prev && prev.id === item.id
          ? {
              ...prev,
              decision: updatedDecision,
              verdict: backendDecision,
              analystReviewed: true,
              status:
                backendDecision === "needs_investigation"
                  ? "under_investigation"
                  : "reviewed",
              raw: {
                ...prev.raw,
                verdict: backendDecision,
                status:
                  backendDecision === "needs_investigation"
                    ? "under_investigation"
                    : "reviewed",
              },
              details: {
                ...(prev.details || {}),
                analyst_decision: data.decision || data.analystDecision || data,
              },
            }
          : prev
      );

      if (selectedAlert?.id === item.id) {
        await openAlertDetails({
          ...item,
          decision: updatedDecision,
          verdict: backendDecision,
          analystReviewed: true,
        });
      }

      await loadTriageQueue(false);

      alert(
        backendDecision === "false_positive"
          ? "Pattern added for false-positive analysis"
          : backendDecision === "true_positive"
          ? "Incident created and escalation initiated"
          : "Investigation incident created"
      );
    } catch (err) {
      console.error("Triage decision save failed:", err);
      alert("Decision save failed. Backend not reachable.");
    }
  };

  const pendingAlerts = rangeFilteredAlerts.filter((i) => !i.analystReviewed);
  const fpAlerts = rangeFilteredAlerts.filter((i) => i.aiDecision === "False Positive");
  const tpAlerts = rangeFilteredAlerts.filter((i) => i.aiDecision === "True Positive");
  const investigateAlerts = rangeFilteredAlerts.filter(
    (i) => i.aiDecision === "Investigate"
  );

  const tabs = [
    { name: "All", label: `All (${rangeFilteredAlerts.length})` },
    { name: "Pending", label: `Pending (${pendingAlerts.length})` },
    { name: "FP", label: `FP (${fpAlerts.length})` },
    { name: "TP", label: `TP (${tpAlerts.length})` },
    { name: "Investigate", label: `Investigate (${investigateAlerts.length})` },
    { name: "Summarize", label: `Summarize (${summaryItems.length})` },
  ];

  const filteredItems =
    activeTab === "All"
      ? rangeFilteredAlerts
      : activeTab === "Pending"
      ? pendingAlerts
      : activeTab === "FP"
      ? fpAlerts
      : activeTab === "TP"
      ? tpAlerts
      : activeTab === "Investigate"
      ? investigateAlerts
      : activeTab === "Summarize"
      ? []
      : rangeFilteredAlerts;

  const selectedDetails = selectedAlert?.details || {};
  const selectedEvidence = normalizeDetailsArray(selectedDetails.evidence);
  const selectedTimeline = normalizeDetailsArray(selectedDetails.timeline);
  const selectedPlaybook = normalizeDetailsArray(
    selectedDetails.playbook || selectedDetails.playbooks
  );
  const selectedAnalystDecision =
    selectedDetails.analyst_decision ||
    selectedDetails.analystDecision ||
    selectedDetails.decision ||
    null;
  const selectedRaw =
    selectedDetails.raw || selectedDetails.rawAlert || selectedAlert?.raw || {};

  return (
    <SiemLayout>
      <div className="triage-page">
        <div className="triage-topbar">
          <div className="triage-tabs">
            {tabs.map((tab) => (
              <button
                key={tab.name}
                className={activeTab === tab.name ? "active" : ""}
                onClick={() => {
                  setActiveTab(tab.name);
                  setSelectedSummary(null);
                }}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className="range-tabs">
            {["1H", "6H", "24H", "3D", "7D", "30D", "ALL"].map((range) => (
              <button
                key={range}
                className={activeRange === range ? "active" : ""}
                onClick={() => {
                  setActiveRange(range);
                  setSelectedSummary(null);
                }}
              >
                {range}
              </button>
            ))}
          </div>
        </div>

        <div className="triage-list">
          {loading ? (
            <div className="triage-empty">Loading AI analyst triage queue...</div>
          ) : activeTab === "Summarize" ? (
            summaryItems.length === 0 ? (
              <div className="triage-empty">
                No summarized alerts found for {activeRange}.
              </div>
            ) : (
              summaryItems.map((item) => (
                <div className="triage-card" key={item.id}>
                  <div className="triage-left">
                    <button
                      className={`decision severity-${item.severity.toLowerCase()}`}
                      onClick={() => setSelectedSummary(item)}
                    >
                      {item.count} Alerts
                    </button>

                    <div className="triage-main">
                      <h3 onClick={() => setSelectedSummary(item)}>
                        {item.title}
                      </h3>

                      <p>
                        Correlated group: agent <b>{item.agent}</b> generated{" "}
                        <b>{item.count}</b> related alert(s) within{" "}
                        <b>{CORRELATION_WINDOW_MINUTES} minutes</b>.
                      </p>

                      <div className="triage-meta">
                        <span>Window: {item.hour}</span>
                        <span>Confidence: {item.confidenceLabel}</span>
                        <span>Agent: {item.agent}</span>
                        <span>Risk: {item.risk}</span>
                      </div>
                    </div>
                  </div>

                  <div className="triage-risk">
                    <span
                      className={`risk-badge severity-${item.severity.toLowerCase()}`}
                    >
                      Risk {item.risk}
                    </span>
                    <div className="risk-line">
                      <div style={{ width: `${item.risk}%` }} />
                    </div>
                    <small>{item.confidenceLabel}</small>
                    <button onClick={() => setSelectedSummary(item)}>▾</button>
                  </div>
                </div>
              ))
            )
          ) : filteredItems.length === 0 ? (
            <div className="triage-empty">
              No triage alerts found for {activeRange}.
            </div>
          ) : (
            filteredItems.map((item) => (
              <div className="triage-card" key={item.id}>
                <div className="triage-left">
                  <span
                    className={`decision severity-${item.severity.toLowerCase()}`}
                  >
                    {item.aiDecision}
                  </span>

                  <div className="triage-main">
                    <h3
                      style={{ cursor: "pointer" }}
                      onClick={() => openAlertDetails(item)}
                    >
                      {item.title}
                    </h3>

                    <p>
                      <b>Reasoning:</b> {item.reasoning}
                    </p>

                    <div className="triage-meta">
                      <span>{item.time}</span>
                      <span>Risk: {item.risk}</span>
                      <span>AI Confidence: {item.confidenceLabel}</span>
                      <span>
                        Analyst: {item.analystReviewed ? item.decision : "Pending"}
                      </span>
                      <span>History: {item.historicalMatches}</span>
                      <span>Threat Intel: {renderValue(item.threatIntel)}</span>
                      <span>Agent: {item.agent}</span>
                      <span>User: {item.username}</span>
                      <span>Process: {item.process}</span>
                    </div>

                    <div className="human-actions">
                      <button
                        onClick={() => markHumanDecision(item, "True Positive")}
                      >
                        Confirm TP
                      </button>
                      <button
                        onClick={() => markHumanDecision(item, "False Positive")}
                      >
                        Confirm FP
                      </button>
                      <button
                        onClick={() => markHumanDecision(item, "Investigate")}
                      >
                        Needs Investigation
                      </button>
                    </div>
                  </div>
                </div>

                <div className="triage-risk">
                  <span
                    className={`risk-badge severity-${item.severity.toLowerCase()}`}
                  >
                    Risk {item.risk}
                  </span>
                  <div className="risk-line">
                    <div style={{ width: `${Math.min(Number(item.risk) || 0, 100)}%` }} />
                  </div>
                  <small>AI {item.confidenceLabel}</small>
                </div>
              </div>
            ))
          )}
        </div>

        {selectedAlert && (
          <div
            className="triage-drawer-overlay"
            onClick={() => setSelectedAlert(null)}
          >
            <div className="triage-drawer" onClick={(e) => e.stopPropagation()}>
              <div className="drawer-header">
                <div>
                  <h2>{selectedAlert.title}</h2>
                  <p>
                    Backend alert details, Claude triage, evidence, timeline,
                    playbook and raw JSON
                  </p>
                </div>
                <button onClick={() => setSelectedAlert(null)}>×</button>
              </div>

              <div className="drawer-summary">
                <div>
                  <label>Alert ID</label>
                  <strong>{selectedAlert.id}</strong>
                </div>
                <div>
                  <label>AI Verdict</label>
                  <strong>{selectedAlert.aiDecision}</strong>
                </div>
                <div>
                  <label>Analyst Decision</label>
                  <strong>
                    {selectedAlert.analystReviewed
                      ? selectedAlert.decision
                      : "Pending"}
                  </strong>
                </div>
                <div>
                  <label>Risk</label>
                  <strong>{selectedAlert.risk}</strong>
                </div>
                <div>
                  <label>Severity</label>
                  <strong>{selectedAlert.severity}</strong>
                </div>
                <div>
                  <label>AI Confidence</label>
                  <strong>{selectedAlert.confidenceLabel}</strong>
                </div>
                <div>
                  <label>Incident Type</label>
                  <strong>{selectedAlert.incidentType}</strong>
                </div>
                <div>
                  <label>Status</label>
                  <strong>{selectedAlert.status}</strong>
                </div>
                <div>
                  <label>Agent</label>
                  <strong>{selectedAlert.agent}</strong>
                </div>
                <div>
                  <label>Timestamp</label>
                  <strong>{selectedAlert.time}</strong>
                </div>
              </div>

              <div className="drawer-alerts">
                {alertDetailsLoading ? (
                  <div className="drawer-alert-card">
                    <div>
                      <h4>Loading backend alert details...</h4>
                      <p>Fetching evidence, timeline, playbook and raw alert.</p>
                    </div>
                  </div>
                ) : selectedDetails.error ? (
                  <div className="drawer-alert-card">
                    <div>
                      <h4>Alert Details Error</h4>
                      <p>{selectedDetails.error}</p>
                    </div>
                  </div>
                ) : null}

                <div className="drawer-alert-card">
                  <div>
                    <h4>Claude / AI Reasoning</h4>
                    <p>{selectedAlert.reasoning}</p>
                  </div>
                </div>

                <div className="drawer-alert-card">
                  <div>
                    <h4>Recommended Action</h4>
                    <p>{selectedAlert.recommendedAction}</p>
                  </div>
                </div>

                <div className="drawer-alert-card">
                  <div style={{ width: "100%" }}>
                    <h4>Backend Evidence</h4>
                    {selectedEvidence.length === 0 ? (
                      <p>No backend evidence found.</p>
                    ) : (
                      selectedEvidence.map((evidence, index) => (
                        <div
                          className="drawer-summary"
                          key={`evidence-${index}`}
                        >
                          {Object.entries(evidence).map(([key, value]) => (
                            <div key={`${key}-${index}`}>
                              <label>{key}</label>
                              <strong>{renderValue(value)}</strong>
                            </div>
                          ))}
                        </div>
                      ))
                    )}
                  </div>
                </div>

                <div className="drawer-alert-card">
                  <div style={{ width: "100%" }}>
                    <h4>Backend Timeline</h4>
                    {selectedTimeline.length === 0 ? (
                      <p>No backend timeline found.</p>
                    ) : (
                      selectedTimeline.map((event, index) => (
                        <div
                          className="drawer-alert-card"
                          key={`${event.title || event.type || "event"}-${index}`}
                        >
                          <div>
                            <h4>{event.title || event.type || "Timeline Event"}</h4>
                            <p>
                              {event.detail ||
                                event.message ||
                                event.description ||
                                "-"}
                            </p>
                            <small>{event.time || event.timestamp || "-"}</small>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                <div className="drawer-alert-card">
                  <div style={{ width: "100%" }}>
                    <h4>Backend Playbook</h4>
                    {selectedPlaybook.length === 0 ? (
                      <p>No playbook actions found.</p>
                    ) : (
                      selectedPlaybook.map((step, index) => (
                        <div
                          className="drawer-alert-card"
                          key={`${step.title || step.action || "playbook"}-${index}`}
                        >
                          <div>
                            <h4>
                              {step.title || step.action || `Step ${index + 1}`}
                            </h4>
                            <p>
                              {step.detail ||
                                step.description ||
                                step.action ||
                                step.status ||
                                "-"}
                            </p>
                            {step.approval_required !== undefined && (
                              <small>
                                Approval required:{" "}
                                {step.approval_required ? "Yes" : "No"}
                              </small>
                            )}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                <div className="drawer-alert-card">
                  <div style={{ width: "100%" }}>
                    <h4>Backend Analyst Decision</h4>
                    <pre
                      style={{
                        whiteSpace: "pre-wrap",
                        wordBreak: "break-word",
                        background: "#081a33",
                        color: "#d7e7ff",
                        padding: "14px",
                        borderRadius: "10px",
                        maxHeight: "220px",
                        overflow: "auto",
                        fontSize: "12px",
                      }}
                    >
                      {JSON.stringify(selectedAnalystDecision, null, 2)}
                    </pre>
                  </div>
                </div>

                <div className="drawer-alert-card">
                  <div style={{ width: "100%" }}>
                    <h4>Analyst Actions</h4>
                    <div className="human-actions">
                      <button
                        onClick={() =>
                          markHumanDecision(selectedAlert, "True Positive")
                        }
                      >
                        Confirm TP
                      </button>
                      <button
                        onClick={() =>
                          markHumanDecision(selectedAlert, "False Positive")
                        }
                      >
                        Confirm FP
                      </button>
                      <button
                        onClick={() =>
                          markHumanDecision(selectedAlert, "Investigate")
                        }
                      >
                        Needs Investigation
                      </button>
                    </div>
                  </div>
                </div>

                <div className="drawer-alert-card">
                  <div style={{ width: "100%" }}>
                    <h4>Backend Raw JSON</h4>
                    <pre
                      style={{
                        whiteSpace: "pre-wrap",
                        wordBreak: "break-word",
                        background: "#081a33",
                        color: "#d7e7ff",
                        padding: "14px",
                        borderRadius: "10px",
                        maxHeight: "320px",
                        overflow: "auto",
                        fontSize: "12px",
                      }}
                    >
                      {JSON.stringify(selectedRaw, null, 2)}
                    </pre>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {selectedSummary && (
          <div
            className="triage-drawer-overlay"
            onClick={() => setSelectedSummary(null)}
          >
            <div className="triage-drawer" onClick={(e) => e.stopPropagation()}>
              <div className="drawer-header">
                <div>
                  <h2>Correlated Alert Group</h2>
                  <p>
                    Same agent + same rule grouped within{" "}
                    {CORRELATION_WINDOW_MINUTES} minutes
                  </p>
                </div>
                <button onClick={() => setSelectedSummary(null)}>×</button>
              </div>

              <div className="drawer-summary">
                <div>
                  <label>Agent</label>
                  <strong>{selectedSummary.agent}</strong>
                </div>
                <div>
                  <label>Rule</label>
                  <strong>{selectedSummary.ruleId}</strong>
                </div>
                <div>
                  <label>Total Alerts</label>
                  <strong>{selectedSummary.count}</strong>
                </div>
                <div>
                  <label>Confidence</label>
                  <strong>{selectedSummary.confidenceLabel}</strong>
                </div>
              </div>

              <div className="drawer-alerts">
                {selectedSummary.relatedAlerts.map((alert) => (
                  <div className="drawer-alert-card" key={alert.id}>
                    <div>
                      <h4
                        style={{ cursor: "pointer" }}
                        onClick={() => openAlertDetails(alert)}
                      >
                        {alert.title}
                      </h4>
                      <p>
                        Agent: <b>{alert.agent}</b> | User:{" "}
                        <b>{alert.username}</b> | Process:{" "}
                        <b>{alert.process}</b>
                      </p>
                      <small>
                        {alert.time} | AI {alert.aiDecision} | Analyst{" "}
                        {alert.analystReviewed ? alert.decision : "Pending"} |
                        Risk {alert.risk} | Confidence {alert.confidenceLabel}
                      </small>

                      <div className="human-actions">
                        <button
                          onClick={() =>
                            markHumanDecision(alert, "True Positive")
                          }
                        >
                          Confirm TP
                        </button>
                        <button
                          onClick={() =>
                            markHumanDecision(alert, "False Positive")
                          }
                        >
                          Confirm FP
                        </button>
                        <button
                          onClick={() =>
                            markHumanDecision(alert, "Investigate")
                          }
                        >
                          Needs Investigation
                        </button>
                      </div>
                    </div>

                    <span
                      className={`risk-badge severity-${alert.severity.toLowerCase()}`}
                    >
                      Risk {alert.risk}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </SiemLayout>
  );
}