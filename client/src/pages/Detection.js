import React, { useEffect, useMemo, useState } from "react";
import SiemLayout from "../components/siem/SiemLayout";
import "../styles/Detection.css";

const API_BASE = "http://10.0.3.83:5000";

export default function Detection() {
  const [patterns, setPatterns] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("All");
  const [expandedId, setExpandedId] = useState(null);

  const getPayloadArray = (payload) => {
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.data)) return payload.data;
    if (Array.isArray(payload?.incidents)) return payload.incidents;
    if (Array.isArray(payload?.patterns)) return payload.patterns;
    if (Array.isArray(payload?.alerts)) return payload.alerts;
    return [];
  };

  const safeNumber = (value, fallback = 0) => {
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
  };

  const percent = (value) => `${Math.round(safeNumber(value) * 100)}%`;

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

  const getAlertPatternKey = (alert) =>
    alert?.pattern_key ||
    alert?.patternKey ||
    alert?.pattern ||
    alert?.alertPatternKey ||
    alert?.learning?.pattern_key ||
    alert?.rawAlert?.pattern_key ||
    "";

  const getIncidentPatternKeys = (incident) => {
    const keys = new Set();

    if (incident?.pattern_key) keys.add(incident.pattern_key);
    if (incident?.patternKey) keys.add(incident.patternKey);

    if (Array.isArray(incident?.evidence)) {
      incident.evidence.forEach((evidence) => {
        if (evidence?.pattern_key) keys.add(evidence.pattern_key);
        if (evidence?.patternKey) keys.add(evidence.patternKey);
        if (evidence?.alert?.pattern_key) keys.add(evidence.alert.pattern_key);
        if (evidence?.rawAlert?.pattern_key) keys.add(evidence.rawAlert.pattern_key);
      });
    }

    if (Array.isArray(incident?.relatedAlerts)) {
      incident.relatedAlerts.forEach((alert) => {
        if (alert?.pattern_key) keys.add(alert.pattern_key);
        if (alert?.patternKey) keys.add(alert.patternKey);
      });
    }

    return Array.from(keys).filter(Boolean);
  };

  const getRuleDescription = (pattern, latestAlert) =>
    pattern.rule_description ||
    pattern.ruleDescription ||
    pattern.description ||
    pattern.title ||
    latestAlert?.rule_description ||
    latestAlert?.ruleDescription ||
    latestAlert?.rule?.description ||
    latestAlert?.rawAlert?.rule?.description ||
    pattern.pattern_key ||
    "-";

  const getRuleId = (pattern, latestAlert) =>
    pattern.rule_id ||
    pattern.ruleId ||
    latestAlert?.rule_id ||
    latestAlert?.ruleId ||
    latestAlert?.rule?.id ||
    latestAlert?.rawAlert?.rule?.id ||
    "-";

  const getRuleFile = (pattern, latestAlert) =>
    pattern.rule_file ||
    pattern.ruleFile ||
    latestAlert?.rule_file ||
    latestAlert?.ruleFile ||
    latestAlert?.rule?.file ||
    latestAlert?.rawAlert?.rule?.file ||
    "local_rules.xml";

  const getAgentName = (pattern, latestAlert) =>
    pattern.agent ||
    pattern.agentName ||
    latestAlert?.agent ||
    latestAlert?.agentName ||
    latestAlert?.agent_name ||
    latestAlert?.rawAlert?.agent?.name ||
    latestAlert?.agent?.name ||
    "-";

  const getProcessName = (pattern, latestAlert) =>
    pattern.process ||
    pattern.processName ||
    latestAlert?.process ||
    latestAlert?.processName ||
    latestAlert?.process_name ||
    latestAlert?.data?.win?.eventdata?.image ||
    latestAlert?.rawAlert?.data?.win?.eventdata?.image ||
    "-";

  const getLatestTimestamp = (...values) => {
    const validDates = values
      .filter(Boolean)
      .map((value) => new Date(value))
      .filter((date) => !Number.isNaN(date.getTime()))
      .sort((a, b) => b.getTime() - a.getTime());

    return validDates.length > 0 ? validDates[0].toISOString() : "-";
  };

  const normalizeStatus = (value) =>
    String(value || "")
      .toLowerCase()
      .replace(/\s+/g, "_")
      .replace(/-/g, "_")
      .trim();

  const getProposalMeta = (row) => {
    const rawStatus = normalizeStatus(
      row.raw?.proposal_status ||
        row.raw?.proposalStatus ||
        row.raw?.deployment_status ||
        row.raw?.deploymentStatus ||
        row.raw?.status ||
        row.status
    );

    if (
      row.raw?.rolled_back ||
      row.raw?.rolledBack ||
      rawStatus.includes("rolled_back") ||
      rawStatus.includes("rollback")
    ) {
      return {
        type: "threshold_increase",
        status: "ROLLED_BACK",
        className: "rolledback",
        tab: "Deployed",
      };
    }

    if (row.raw?.rejected || rawStatus.includes("rejected") || rawStatus.includes("declined")) {
      return {
        type: "new_rule",
        status: "REJECTED",
        className: "rejected",
        tab: "Rejected",
      };
    }

    if (row.raw?.approved || rawStatus.includes("approved")) {
      return {
        type: row.suppression ? "exclusion_added" : "new_rule",
        status: "APPROVED",
        className: "approved",
        tab: "Approved",
      };
    }

    if (
      row.raw?.deployed ||
      row.suppression ||
      rawStatus.includes("deployed") ||
      rawStatus.includes("suppression")
    ) {
      return {
        type: "exclusion_added",
        status: "DEPLOYED",
        className: "deployed",
        tab: "Deployed",
      };
    }

    if (
      row.raw?.manual_fix ||
      row.raw?.manualFix ||
      row.dangerous ||
      rawStatus.includes("manual") ||
      rawStatus.includes("dangerous")
    ) {
      return {
        type: "new_rule",
        status: "MANUAL FIX NEEDED",
        className: "manual",
        tab: "Manual",
      };
    }

    return {
      type: "new_rule",
      status: "PROPOSED",
      className: "proposed",
      tab: "Proposed",
    };
  };

  useEffect(() => {
    let cancelled = false;

    async function loadDetectionData() {
      try {
        setLoading(true);

        const [patternsRes, alertsRes, incidentsRes] = await Promise.all([
          fetch(`${API_BASE}/api/wazuh/alert-patterns?limit=50`),
          fetch(`${API_BASE}/api/wazuh/analyst-queue?limit=50`),
          fetch(`${API_BASE}/api/incidents?limit=10`),
        ]);

        const [patternsData, alertsData, incidentsData] = await Promise.all([
          patternsRes.json(),
          alertsRes.json(),
          incidentsRes.json(),
        ]);

        if (cancelled) return;

        setPatterns(getPayloadArray(patternsData));
        setAlerts(getPayloadArray(alertsData));
        setIncidents(getPayloadArray(incidentsData));
      } catch (err) {
        console.error("Detection fetch error:", err);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    loadDetectionData();
    const interval = setInterval(loadDetectionData, 60000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const detectionRows = useMemo(() => {
    const sortedAlerts = [...alerts].sort((a, b) => {
      const dateA = new Date(a.createdAt || a.timestamp || a.lastSeen || 0).getTime();
      const dateB = new Date(b.createdAt || b.timestamp || b.lastSeen || 0).getTime();
      return dateB - dateA;
    });

    return patterns
      .filter((pattern) => {
        const key = String(
          pattern.pattern_key ||
            pattern.patternKey ||
            pattern.rule_description ||
            pattern.title ||
            ""
        ).toLowerCase();

        return !(key.includes("pam-login-session") && safeNumber(pattern.occurrences) < 50);
      })
      .map((pattern) => {
        const patternKey = pattern.pattern_key || pattern.patternKey || pattern._id || "";

        const relatedAlerts = sortedAlerts.filter(
          (alert) => getAlertPatternKey(alert) === patternKey
        );

        const relatedIncidents = incidents.filter((incident) =>
          getIncidentPatternKeys(incident).includes(patternKey)
        );

        const latestAlert = relatedAlerts[0];

        const riskMax = Math.min(
          Math.max(
            safeNumber(pattern.riskScore || pattern.risk || pattern.max_risk || pattern.last_risk),
            ...relatedAlerts.map((item) =>
              safeNumber(item.risk || item.riskScore || item.aiRisk || item.finalRisk)
            ),
            ...relatedIncidents.map((item) =>
              safeNumber(item.riskScore || item.risk || item.aiRisk || item.finalRisk)
            ),
            0
          ),
          100
        );

        const fpRate = safeNumber(pattern.fp_rate || pattern.fpRate);
        const tpRate = safeNumber(pattern.tp_rate || pattern.tpRate);
        const aiAccuracy = safeNumber(
          pattern.ai_accuracy_rate || pattern.aiAccuracyRate || pattern.aiAccuracy
        );

        const fpCount = safeNumber(pattern.fp_count || pattern.fpCount);
        const tpCount = safeNumber(pattern.tp_count || pattern.tpCount);
        const investigationCount = safeNumber(
          pattern.investigation_count || pattern.investigationCount
        );

        const occurrences = Math.max(
          safeNumber(pattern.occurrences || pattern.count || pattern.total_count || pattern.totalCount),
          relatedAlerts.length
        );

        const suppression = Boolean(pattern.suppression_candidate || pattern.suppressionCandidate);
        const autoClose = Boolean(pattern.auto_close_eligible || pattern.autoCloseEligible);
        const dangerous = Boolean(pattern.dangerous_pattern || pattern.dangerousPattern);
        const aiQualityRisk = Boolean(pattern.ai_quality_risk || pattern.aiQualityRisk);

        const status =
          pattern.last_analyst_decision ||
          pattern.lastAnalystDecision ||
          pattern.status ||
          latestAlert?.verdict ||
          latestAlert?.status ||
          "Monitoring";

        const recommendedAction =
          pattern.recommendedAction ||
          pattern.recommended_action ||
          pattern.last_reason ||
          pattern.lastReason ||
          latestAlert?.recommended_action ||
          latestAlert?.recommendedAction ||
          latestAlert?.reasoning ||
          latestAlert?.ai_reasoning ||
          latestAlert?.triageReason ||
          "-";

        const lastSeen = getLatestTimestamp(
          pattern.last_seen,
          pattern.lastSeen,
          pattern.updatedAt,
          pattern.createdAt,
          latestAlert?.createdAt,
          latestAlert?.timestamp,
          latestAlert?.lastSeen,
          relatedIncidents[0]?.lastSeen,
          relatedIncidents[0]?.updatedAt
        );

        return {
          id: pattern._id || patternKey || `${getRuleId(pattern, latestAlert)}-${lastSeen}`,
          patternKey,
          rule: getRuleDescription(pattern, latestAlert),
          ruleId: getRuleId(pattern, latestAlert),
          ruleFile: getRuleFile(pattern, latestAlert),
          agent: getAgentName(pattern, latestAlert),
          process: getProcessName(pattern, latestAlert),
          occurrences,
          fpCount,
          tpCount,
          investigationCount,
          fpRate,
          tpRate,
          aiAccuracy,
          risk: riskMax,
          status,
          suppression,
          autoClose,
          dangerous,
          aiQualityRisk,
          incidents: relatedIncidents.length,
          alerts: relatedAlerts.length,
          lastSeen,
          recommendedAction,
          relatedAlerts,
          relatedIncidents,
          raw: pattern,
        };
      })
      .map((row) => {
        const meta = getProposalMeta(row);
        return {
          ...row,
          proposalType: meta.type,
          proposalStatus: meta.status,
          proposalClass: meta.className,
          proposalTab: meta.tab,
        };
      });
  }, [patterns, alerts, incidents]);

  const counts = useMemo(() => {
    return {
      all: detectionRows.length,
      proposed: detectionRows.filter((item) => item.proposalTab === "Proposed").length,
      approved: detectionRows.filter((item) => item.proposalTab === "Approved").length,
      deployed: detectionRows.filter((item) => item.proposalTab === "Deployed").length,
      rejected: detectionRows.filter((item) => item.proposalTab === "Rejected").length,
      manual: detectionRows.filter((item) => item.proposalTab === "Manual").length,
    };
  }, [detectionRows]);

  const filteredRows = useMemo(() => {
    return detectionRows
      .filter((item) => {
        if (activeTab === "All") return true;
        return item.proposalTab === activeTab;
      })
      .sort((a, b) => {
        const dateA = new Date(a.lastSeen || 0).getTime();
        const dateB = new Date(b.lastSeen || 0).getTime();
        return dateB - dateA;
      });
  }, [detectionRows, activeTab]);

  const tabs = [
    { name: "All", label: `All (${counts.all})` },
    { name: "Proposed", label: `Proposed (${counts.proposed})` },
    { name: "Approved", label: `Approved (${counts.approved})` },
    { name: "Deployed", label: `Deployed (${counts.deployed})` },
    { name: "Rejected", label: `Rejected (${counts.rejected})` },
    { name: "Manual", label: `Manual Fix (${counts.manual})` },
  ];

  const buildRuleXml = (item) => {
    const hostname = item.agent && item.agent !== "-" ? item.agent : "any";
    const process = item.process && item.process !== "-" ? item.process : "any";

    return `<rule id="${item.ruleId}" level="0">
  <if_sid>${item.ruleId}</if_sid>
  <hostname>${hostname}</hostname>
  <description>
    ${item.rule}
  </description>
  <field name="process">${process}</field>
  <options>no_log</options>
</rule>`;
  };

  return (
    <SiemLayout>
      <div className="detection-page">
        <div className="detection-topbar">
          <div className="detection-tabs">
            {tabs.map((tab) => (
              <button
                key={tab.name}
                className={activeTab === tab.name ? "active" : ""}
                onClick={() => {
                  setActiveTab(tab.name);
                  setExpandedId(null);
                }}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className="detection-actions">
            <button className="approve-all">✓ Approve All ({counts.proposed})</button>
            <button className="run-agent">Run Tuning Agent</button>
          </div>
        </div>

        <div className="detection-list">
          {loading ? (
            <div className="detection-empty">Loading detection proposals...</div>
          ) : filteredRows.length === 0 ? (
            <div className="detection-empty">No detection proposals found.</div>
          ) : (
            filteredRows.map((item) => {
              const expanded = expandedId === item.id;

              return (
                <div className={expanded ? "proposal-card expanded" : "proposal-card"} key={item.id}>
                  <div
                    className="proposal-row"
                    onClick={() => setExpandedId(expanded ? null : item.id)}
                  >
                    <div className="proposal-left">
                      <div className="proposal-mainline">
                        <span className="proposal-chip">{item.proposalType}</span>

                        <h3>
                          Rule {item.ruleId}
                          <small>{item.ruleFile}</small>
                        </h3>

                        <span className={`proposal-state inline ${item.proposalClass}`}>
                          {item.proposalStatus}
                        </span>
                      </div>

                      <p>Click to view proposal details</p>

                      <div className="proposal-desc">{item.rule}</div>
                    </div>

                    <div className="proposal-right">
                      <small>{formatDateTime(item.lastSeen)}</small>
                      <span className="proposal-arrow">{expanded ? "▲" : "▼"}</span>
                    </div>
                  </div>

                  {expanded && (
                    <div className="proposal-expanded">
                      <div className="proposal-detail-grid">
                        <div className="proposal-detail-box">
                          <h4>Current Issue</h4>
                          <p>
                            Rule {item.ruleId} repeatedly generated alerts on {item.agent}. Pattern
                            learning detected {item.fpCount} false positives and {item.tpCount} true
                            positives from {item.occurrences} observed alerts.
                          </p>
                        </div>

                        <div className="proposal-detail-box">
                          <h4>FP Pattern Identified</h4>
                          <p>
                            FP ratio: {percent(item.fpRate)} from {item.occurrences} observed alerts.
                            TP ratio: {percent(item.tpRate)}.
                          </p>
                        </div>
                      </div>

                      <div className="proposal-section">
                        <h4>Proposed Rule XML</h4>
                        <pre>{buildRuleXml(item)}</pre>
                      </div>

                      <div className="proposal-section">
                        <h4>Changes Made</h4>
                        <ul>
                          <li>Generated from Wazuh alert patterns and analyst learning data.</li>
                          <li>Rule file: {item.ruleFile}</li>
                          <li>Process: {item.process}</li>
                          <li>Status: {item.proposalStatus}</li>
                          <li>Related alerts: {item.alerts}</li>
                          <li>Related incidents: {item.incidents}</li>
                        </ul>
                      </div>

                      <div className="fp-reduction-box">
                        <h4>Expected FP Reduction</h4>
                        <strong>
                          {percent(item.fpRate)} false-positive reduction estimated from the learned
                          pattern.
                        </strong>
                      </div>

                      <div className="coverage-impact-box">
                        <h4>Coverage Impact</h4>
                        <strong>
                          Suppression only affects learned repetitive behavior for this rule pattern.
                          Parent detection remains active for unknown or changed activity.
                        </strong>
                      </div>

                      <div className="fp-trigger-box">
                        <h4>FP Trigger</h4>
                        <strong>{item.fpCount} FPs in learned window</strong>
                      </div>

                      <div className="proposal-section">
                        <h4>Coverage Risk Assessment</h4>
                        <p>
                          Risk score: {item.risk}. AI accuracy: {percent(item.aiAccuracy)}. Analyst
                          status: {item.status}. Recommended action: {item.recommendedAction}
                        </p>
                      </div>

                      <div className="proposal-section">
                        <h4>Testing Recommendations</h4>
                        <ol>
                          <li>Deploy the rule change in a test environment first.</li>
                          <li>Verify that known false-positive behavior no longer generates noise.</li>
                          <li>Confirm suspicious behavior is still detected by the parent rule.</li>
                          <li>Run rule validation with representative Wazuh alert samples.</li>
                          <li>Monitor for 48–72 hours after deployment.</li>
                        </ol>
                      </div>

                      <div className="proposal-footer">
                        <span className={`proposal-state ${item.proposalClass}`}>
                          {item.proposalStatus}
                        </span>

                        <span>{formatDateTime(item.lastSeen)}</span>

                        <div>
                          <button className="rollback-btn">↩ Rollback</button>
                          <button className="approve-btn">Approve Rule</button>
                        </div>
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