import React, { useEffect, useState } from "react";
import SiemLayout from "../components/siem/SiemLayout";
import "../styles/Patterns.css";

const API_BASE = "http://10.0.3.83:5000";

export default function Patterns() {
  const [patterns, setPatterns] = useState([]);
  const [loading, setLoading] = useState(true);

  const getArray = (payload) => {
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.data)) return payload.data;
    if (Array.isArray(payload?.patterns)) return payload.patterns;
    return [];
  };

  useEffect(() => {
    async function loadPatterns() {
      try {
        setLoading(true);
        const res = await fetch(`${API_BASE}/api/wazuh/alert-patterns?limit=500`);
        const data = await res.json();
        setPatterns(getArray(data));
      } catch (err) {
        console.error("Patterns fetch error:", err);
        setPatterns([]);
      } finally {
        setLoading(false);
      }
    }

    loadPatterns();
  }, []);

  return (
    <SiemLayout>
      <div className="patterns-page">
        <h2>Detection Learning Patterns</h2>
        <p className="patterns-subtitle">
          Tracks repeated analyst decisions, false-positive rate, true-positive rate,
          AI quality risk, and suppression readiness.
        </p>

        {loading ? (
          <div className="patterns-empty">Loading patterns...</div>
        ) : patterns.length === 0 ? (
          <div className="patterns-empty">No learning patterns found yet.</div>
        ) : (
          <div className="patterns-grid">
            {patterns.map((item) => (
              <div className="pattern-card" key={item._id || item.pattern_key}>
                <div className="pattern-top">
                  <span className="pattern-agent">{item.agent || "-"}</span>
                  <span
                    className={
                      item.dangerous_pattern
                        ? "pattern-badge danger"
                        : item.suppression_candidate
                        ? "pattern-badge warning"
                        : "pattern-badge safe"
                    }
                  >
                    {item.dangerous_pattern
                      ? "Threat Pattern"
                      : item.suppression_candidate
                      ? "Suppression Candidate"
                      : "Monitoring"}
                  </span>
                </div>

                <h3>{item.rule_description || item.title || item.pattern_key}</h3>

                <div className="pattern-stats">
                  <div>
                    <small>Occurrences</small>
                    <b>{item.occurrences || 0}</b>
                  </div>
                  <div>
                    <small>FP Count</small>
                    <b>{item.fp_count || 0}</b>
                  </div>
                  <div>
                    <small>TP Count</small>
                    <b>{item.tp_count || 0}</b>
                  </div>
                  <div>
                    <small>FP Rate</small>
                    <b>{Math.round((item.fp_rate || 0) * 100)}%</b>
                  </div>
                </div>

                <div className="pattern-footer">
                  <span>Process: {item.process || "-"}</span>
                  <span>Risk: {item.riskScore || item.last_risk || 0}</span>
                  <span>
                    Auto-close: {item.auto_close_eligible ? "Eligible" : "No"}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </SiemLayout>
  );
}