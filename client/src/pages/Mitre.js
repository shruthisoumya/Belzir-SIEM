import React, { useEffect, useMemo, useState } from "react";
import SiemLayout from "../components/siem/SiemLayout";
import "../styles/Mitre.css";

const API_BASE = "http://10.0.3.83:5000";

export default function Mitre() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedTechnique, setSelectedTechnique] = useState(null);

  const getArray = (payload) => {
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.data)) return payload.data;
    if (Array.isArray(payload?.items)) return payload.items;
    if (Array.isArray(payload?.alerts)) return payload.alerts;
    return [];
  };

  const safeNumber = (value, fallback = 0) => {
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
  };

  const normalizeArray = (value) => {
    if (Array.isArray(value)) return value.filter(Boolean);
    if (!value || value === "-") return [];
    return [value];
  };

  const normalizeTactic = (value) =>
    String(value || "Unmapped")
      .replace(/-/g, " ")
      .replace(/_/g, " ")
      .trim()
      .replace(/\w\S*/g, (txt) => txt.charAt(0).toUpperCase() + txt.slice(1).toLowerCase());

  const formatTime = (value) => {
    if (!value || value === "-") return "-";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleTimeString("en-GB", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  useEffect(() => {
    let cancelled = false;

    async function loadData() {
      try {
        setLoading(true);

        const res = await fetch(`${API_BASE}/api/wazuh/mitre-lite?limit=500`);
        const data = await res.json();

        if (cancelled) return;

        setItems(getArray(data));
      } catch (err) {
        console.error("MITRE fetch error:", err);
        setItems([]);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    loadData();

    const interval = setInterval(loadData, 180000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const normalizedItems = useMemo(() => {
    return items.map((item, index) => {
      const risk = safeNumber(item.risk || item.riskScore || item.level);

      const tactics = normalizeArray(item.tactics || item.tactic).map(normalizeTactic);
      const techniques = normalizeArray(item.techniques || item.technique);
      const ids = normalizeArray(item.ids || item.mitreIds || item.mitre_ids);

      return {
        id: item.alert_id || item.id || item._id || `mitre-${index}`,
        title: item.title || item.rule_description || item.description || "-",
        host: item.host || item.agent || item.agentName || "-",
        process: item.process || "-",
        user: item.user || item.username || "-",
        risk,
        confidence: safeNumber(item.confidence || item.aiConfidence),
        verdict: item.verdict || "-",
        tactics,
        techniques,
        ids,
        timestamp: item.timestamp || item.createdAt || item.updatedAt || "-",
      };
    });
  }, [items]);

  const tacticCoverage = useMemo(() => {
    const map = new Map();

    normalizedItems.forEach((item) => {
      const tactics = item.tactics.length ? item.tactics : ["Unmapped"];
      const ids = item.ids.length ? item.ids : item.techniques;

      tactics.forEach((tactic) => {
        if (!map.has(tactic)) {
          map.set(tactic, {
            tactic,
            detected: new Set(),
            events: 0,
          });
        }

        const entry = map.get(tactic);
        entry.events += 1;

        ids.forEach((id) => entry.detected.add(id));
      });
    });

    return Array.from(map.values())
      .map((entry) => ({
        tactic: entry.tactic,
        detected: entry.detected.size,
        events: entry.events,
      }))
      .sort((a, b) => b.detected - a.detected || b.events - a.events);
  }, [normalizedItems]);

  const techniqueGroups = useMemo(() => {
    const map = new Map();

    normalizedItems.forEach((item) => {
      const tactics = item.tactics.length ? item.tactics : ["Unmapped"];
      const ids = item.ids.length ? item.ids : item.techniques.length ? item.techniques : ["Unmapped"];

      tactics.forEach((tactic) => {
        if (!map.has(tactic)) map.set(tactic, new Map());

        ids.forEach((id) => {
          const key = String(id);
          const tacticMap = map.get(tactic);

          if (!tacticMap.has(key)) {
            tacticMap.set(key, {
              id: key,
              tactic,
              name: item.techniques[0] || item.title || key,
              detections: 0,
              tp: 0,
              fp: 0,
              lastSeen: item.timestamp,
              risk: item.risk,
              status: "active",
            });
          }

          const technique = tacticMap.get(key);
          technique.detections += 1;
          technique.risk = Math.max(technique.risk, item.risk);
          technique.lastSeen = item.timestamp || technique.lastSeen;

          const verdict = String(item.verdict || "").toLowerCase();

          if (verdict.includes("true")) technique.tp += 1;
          if (verdict.includes("false")) technique.fp += 1;
        });
      });
    });

    return Array.from(map.entries()).map(([tactic, values]) => ({
      tactic,
      techniques: Array.from(values.values()).sort(
        (a, b) => b.detections - a.detections || b.risk - a.risk
      ),
    }));
  }, [normalizedItems]);

  const allTechniques = useMemo(() => {
    return techniqueGroups.flatMap((group) => group.techniques);
  }, [techniqueGroups]);

  const stats = useMemo(() => {
    const totalTechniques = allTechniques.length;
    const active = allTechniques.filter((technique) => technique.detections > 0).length;
    const coverage = totalTechniques ? active / totalTechniques : 0;

    return {
      coverage,
      detected: active,
      gaps: Math.max(totalTechniques - active, 0),
      total: totalTechniques,
    };
  }, [allTechniques]);

  return (
    <SiemLayout>
      <div className="mitre-page">
        <div className="mitre-header">
          <h1>MITRE ATT&CK Coverage</h1>
          <p>Detection coverage mapped to the ATT&CK Enterprise matrix.</p>
        </div>

        <div className="mitre-summary">
          <div>
            <h2>{loading ? "..." : `${Math.round(stats.coverage * 100)}%`}</h2>
            <p>Coverage</p>
            <span>of techniques detected</span>
          </div>

          <div>
            <h2>{loading ? "..." : stats.detected}</h2>
            <p>Detected</p>
            <span>unique techniques</span>
          </div>

          <div>
            <h2>{loading ? "..." : stats.gaps}</h2>
            <p>Gaps</p>
            <span>not detected</span>
          </div>

          <div>
            <h2>{loading ? "..." : stats.total}</h2>
            <p>Total</p>
            <span>in current matrix</span>
          </div>
        </div>

        <div className="coverage-section">
          <h3>Coverage by Tactic</h3>

          {loading ? (
            <div className="mitre-empty">Loading MITRE coverage...</div>
          ) : tacticCoverage.length === 0 ? (
            <div className="mitre-empty">No MITRE coverage found.</div>
          ) : (
            tacticCoverage.map((item) => {
              const maxDetected = Math.max(...tacticCoverage.map((tactic) => tactic.detected), 1);
              const width = Math.max((item.detected / maxDetected) * 100, 4);

              return (
                <div className="coverage-row" key={item.tactic}>
                  <span>{item.tactic}</span>

                  <div className="coverage-bar">
                    <div style={{ width: `${width}%` }} />
                  </div>

                  <strong>
                    {item.detected}/{maxDetected} ({Math.round((item.detected / maxDetected) * 100)}%)
                  </strong>
                </div>
              );
            })
          )}
        </div>

        <div className="heatmap-section">
          <h3>Technique Heatmap</h3>

          <div className="heatmap-grid">
            {techniqueGroups.map((group) => (
              <div className="heatmap-column" key={group.tactic}>
                <h4>{group.tactic}</h4>

                {group.techniques.map((technique) => (
                  <button
                    key={`${group.tactic}-${technique.id}`}
                    className={
                      technique.risk >= 70
                        ? "heatmap-cell active"
                        : technique.fp > technique.tp
                        ? "heatmap-cell noisy"
                        : "heatmap-cell detected"
                    }
                    onClick={() => setSelectedTechnique(technique)}
                  >
                    {technique.id}
                  </button>
                ))}
              </div>
            ))}
          </div>

          <div className="heatmap-legend">
            <span>
              <b className="legend-active" /> Active
            </span>
            <span>
              <b className="legend-noisy" /> Noisy
            </span>
            <span>
              <b className="legend-detected" /> Detected
            </span>
          </div>
        </div>

        <div className="gap-section">
          <h3>Detection Gaps ({stats.gaps} techniques)</h3>

          <div className="gap-grid">
            {techniqueGroups.map((group) => (
              <div className="gap-card" key={group.tactic}>
                <h4>
                  {group.tactic} ({group.techniques.length})
                </h4>

                {group.techniques.map((technique) => (
                  <p key={`${group.tactic}-${technique.id}`}>
                    {technique.id} {technique.name}
                  </p>
                ))}
              </div>
            ))}
          </div>
        </div>

        {selectedTechnique && (
          <div className="technique-detail">
            <div>
              <h3>
                {selectedTechnique.id} {selectedTechnique.name}
              </h3>
              <span>{selectedTechnique.tactic}</span>
            </div>

            <div className="technique-meta">
              <span className="active-chip">active</span>
              <span>Detections: {selectedTechnique.detections}</span>
              <span>TP: {selectedTechnique.tp}</span>
              <span>FP: {selectedTechnique.fp}</span>
              <span>Last seen: {formatTime(selectedTechnique.lastSeen)}</span>
            </div>

            <button onClick={() => setSelectedTechnique(null)}>Close</button>
          </div>
        )}
      </div>
    </SiemLayout>
  );
}