import React, { useEffect, useMemo, useState } from "react";
import SiemLayout from "../components/siem/SiemLayout";
import "../styles/ClosedLoop.css";

const API_BASE = "http://10.0.3.83:5000";

export default function ClosedLoop() {
  const [patterns, setPatterns] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);

  const getArray = (payload) => {
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.data)) return payload.data;
    if (Array.isArray(payload?.patterns)) return payload.patterns;
    if (Array.isArray(payload?.alerts)) return payload.alerts;
    if (Array.isArray(payload?.incidents)) return payload.incidents;
    return [];
  };

  const safeNumber = (value, fallback = 0) => {
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
  };

  const percent = (value) => `${Math.round(safeNumber(value) * 100)}%`;

useEffect(() => {
  let cancelled = false;

  async function loadClosedLoop() {
    try {
      setLoading(true);

      const [patternsRes, alertsRes, incidentsRes] = await Promise.allSettled([
        fetch(`${API_BASE}/api/wazuh/alert-patterns?limit=20`),
        fetch(`${API_BASE}/api/wazuh/analyst-queue?limit=20`),
        fetch(`${API_BASE}/api/incidents?limit=5`),
      ]);

      const patternsData =
        patternsRes.status === "fulfilled" ? await patternsRes.value.json() : {};

      const alertsData =
        alertsRes.status === "fulfilled" ? await alertsRes.value.json() : {};

      const incidentsData =
        incidentsRes.status === "fulfilled" ? await incidentsRes.value.json() : {};

      if (cancelled) return;

      setPatterns(getArray(patternsData));
      setAlerts(getArray(alertsData));
      setIncidents(getArray(incidentsData));
    } catch (err) {
      console.error("Closed Loop fetch error:", err);

      if (!cancelled) {
        setPatterns([]);
        setAlerts([]);
        setIncidents([]);
      }
    } finally {
      if (!cancelled) setLoading(false);
    }
  }

  loadClosedLoop();

  const interval = setInterval(loadClosedLoop, 120000);

  return () => {
    cancelled = true;
    clearInterval(interval);
  };
}, []);

  const rows = useMemo(() => {
    return patterns.map((pattern) => {
      const fpRate = safeNumber(pattern.fp_rate || pattern.fpRate);
      const confidence = safeNumber(
        pattern.last_confidence ||
          pattern.lastConfidence ||
          pattern.ai_confidence ||
          pattern.aiConfidence
      );
      const aiCorrect = safeNumber(pattern.ai_correct_count || pattern.aiCorrectCount);
      const aiWrong = safeNumber(pattern.ai_wrong_count || pattern.aiWrongCount);
      const aiAccuracy =
        aiCorrect + aiWrong > 0
          ? aiCorrect / (aiCorrect + aiWrong)
          : safeNumber(pattern.ai_accuracy_rate || pattern.aiAccuracyRate);

      return {
        fpRate,
        confidence,
        aiAccuracy,
        suppression: Boolean(pattern.suppression_candidate || pattern.suppressionCandidate),
        autoClose: Boolean(pattern.auto_close_eligible || pattern.autoCloseEligible),
        dangerous: Boolean(pattern.dangerous_pattern || pattern.dangerousPattern),
        aiQuality: Boolean(pattern.ai_quality_risk || pattern.aiQualityRisk),
      };
    });
  }, [patterns]);

  const summary = useMemo(() => {
    const totalFpRate = rows.reduce((sum, item) => sum + item.fpRate, 0);
    const totalConfidence = rows.reduce((sum, item) => sum + item.confidence, 0);

    const fpRate = rows.length ? totalFpRate / rows.length : 0;
    const confidence = rows.length ? totalConfidence / rows.length : 0;

    const automationReady = rows.filter(
      (item) => item.suppression || item.autoClose
    ).length;

    const automation = rows.length ? automationReady / rows.length : 0;

    const reviewPending = alerts.filter((alert) => {
      const verdict = String(alert.verdict || alert.status || "").toLowerCase();
      return (
        verdict.includes("review") ||
        verdict.includes("investigation") ||
        verdict.includes("pending")
      );
    }).length;

    return {
      alerts: alerts.length,
      triageConfidence: confidence,
      reviewPending,
      fpDetect: rows.filter((item) => item.fpRate > 0).length,
      tune: rows.filter((item) => item.suppression || item.autoClose).length,
      deploy: rows.filter((item) => item.suppression).length,
      fpRate,
      automation,
      confidence,
      incidents: incidents.length,
    };
  }, [rows, alerts, incidents]);

  return (
    <SiemLayout>
      <div className="closedloop-page">
        <div className="closedloop-loop-card">
          <h2>THE COMPOUNDING LOOP</h2>

          <div className="loop-flow">
            <div className="loop-step">
              <div className="loop-icon">🚨</div>
              <strong>Alerts</strong>
              <span>{loading ? "..." : summary.alerts}</span>
            </div>

            <div className="loop-arrow">→</div>

            <div className="loop-step">
              <div className="loop-icon">🤖</div>
              <strong>Triage</strong>
              <span>{loading ? "..." : percent(summary.triageConfidence)}</span>
            </div>

            <div className="loop-arrow">→</div>

            <div className="loop-step">
              <div className="loop-icon">👁️</div>
              <strong>Review</strong>
              <span>{loading ? "..." : `${summary.reviewPending} pending`}</span>
            </div>

            <div className="loop-arrow">→</div>

            <div className="loop-step">
              <div className="loop-icon">📊</div>
              <strong>FP Detect</strong>
              <span>{loading ? "..." : `${summary.fpDetect} rules`}</span>
            </div>

            <div className="loop-arrow">→</div>

            <div className="loop-step">
              <div className="loop-icon">🔧</div>
              <strong>Tune</strong>
              <span>{loading ? "..." : `${summary.tune} proposals`}</span>
            </div>

            <div className="loop-arrow">→</div>

            <div className="loop-step">
              <div className="loop-icon">✅</div>
              <strong>Deploy</strong>
              <span>{loading ? "..." : summary.deploy > 0 ? "Loop closes" : "Waiting"}</span>
            </div>
          </div>
        </div>

        <div className="closedloop-metric-grid">
          <div className="closedloop-metric-card yellow">
            <h3>{loading ? "..." : percent(summary.fpRate)}</h3>
            <p>FP RATE</p>
          </div>

          <div className="closedloop-metric-card dark">
            <h3>{loading ? "..." : percent(summary.automation)}</h3>
            <p>AUTOMATION</p>
          </div>

          <div className="closedloop-metric-card blue">
            <h3>{loading ? "..." : percent(summary.confidence)}</h3>
            <p>CONFIDENCE</p>
          </div>
        </div>
      </div>
    </SiemLayout>
  );
}