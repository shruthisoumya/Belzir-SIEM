import React, { useEffect, useMemo, useState } from "react";
import SiemLayout from "../components/siem/SiemLayout";
import "../styles/Investigation.css";

const API_BASE = "http://10.0.3.83:5000";

export default function Investigation() {
  const [incidents, setIncidents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [query, setQuery] = useState("");
  const [answer, setAnswer] = useState("");
  const [loading, setLoading] = useState(true);
  const [asking, setAsking] = useState(false);

  const getArray = (payload) => {
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.data)) return payload.data;
    if (Array.isArray(payload?.alerts)) return payload.alerts;
    if (Array.isArray(payload?.incidents)) return payload.incidents;
    return [];
  };

  const safeNumber = (value, fallback = 0) => {
    const n = Number(value);
    return Number.isFinite(n) ? n : fallback;
  };

  const formatTimeRange = (items) => {
    const times = items
      .map((a) => new Date(a.timestamp || a.createdAt || a.updatedAt))
      .filter((d) => !Number.isNaN(d.getTime()))
      .sort((a, b) => a - b);

    if (!times.length) return "";

    const first = times[0].toLocaleTimeString("en-GB", {
      hour: "2-digit",
      minute: "2-digit",
    });

    const last = times[times.length - 1].toLocaleTimeString("en-GB", {
      hour: "2-digit",
      minute: "2-digit",
    });

    return `${first}–${last}`;
  };

  const getRule = (alert) =>
    alert?.rule_description ||
    alert?.ruleDescription ||
    alert?.rule?.description ||
    alert?.rawAlert?.rule?.description ||
    "Unknown rule";

  const getRuleId = (alert) =>
    alert?.rule_id ||
    alert?.ruleId ||
    alert?.rule?.id ||
    alert?.rawAlert?.rule?.id ||
    "-";

  const getRuleLevel = (alert) =>
    safeNumber(
      alert?.rule_level ||
        alert?.ruleLevel ||
        alert?.rule?.level ||
        alert?.rawAlert?.rule?.level
    );

  const getAgent = (alert) =>
    alert?.agent ||
    alert?.agentName ||
    alert?.agent_name ||
    alert?.rawAlert?.agent?.name ||
    alert?.agent?.name ||
    "-";

  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true);

        const [alertsRes, incidentsRes] = await Promise.all([
          fetch(`${API_BASE}/api/wazuh/analyst-queue?limit=500`),
          fetch(`${API_BASE}/api/incidents?limit=200`),
        ]);

        const [alertsData, incidentsData] = await Promise.all([
          alertsRes.json(),
          incidentsRes.json(),
        ]);

        const alertRows = getArray(alertsData);
        const incidentRows = getArray(incidentsData);

        setAlerts(alertRows);
        setIncidents(incidentRows);

        setAnswer(buildAnswer(alertRows, incidentRows));
      } catch (err) {
        console.error("Investigation load error:", err);
        setAnswer("Unable to load investigation data from Wazuh at the moment.");
      } finally {
        setLoading(false);
      }
    }

    loadData();
  }, []);

  const lastHourAlerts = useMemo(() => {
    const now = Date.now();
    const oneHourAgo = now - 60 * 60 * 1000;

    return alerts.filter((alert) => {
      const time = new Date(alert.timestamp || alert.createdAt || alert.updatedAt).getTime();
      return Number.isFinite(time) && time >= oneHourAgo;
    });
  }, [alerts]);

  const summaryRows = useMemo(() => {
    const map = new Map();

    const source = lastHourAlerts.length ? lastHourAlerts : alerts.slice(0, 50);

    source.forEach((alert) => {
      const ruleId = getRuleId(alert);
      const description = getRule(alert);
      const level = getRuleLevel(alert);
      const agent = getAgent(alert);

      const key = `${ruleId}-${description}`;

      if (!map.has(key)) {
        map.set(key, {
          ruleId,
          description,
          level,
          count: 0,
          agents: new Set(),
        });
      }

      const row = map.get(key);
      row.count += 1;
      if (agent && agent !== "-") row.agents.add(agent);
      row.level = Math.max(row.level, level);
    });

    return Array.from(map.values())
      .map((row) => ({
        ...row,
        agents: Array.from(row.agents).join(", ") || "-",
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 12);
  }, [alerts, lastHourAlerts]);

  function buildAnswer(alertRows, incidentRows) {
    const now = Date.now();
    const oneHourAgo = now - 60 * 60 * 1000;

    const recent = alertRows.filter((alert) => {
      const time = new Date(alert.timestamp || alert.createdAt || alert.updatedAt).getTime();
      return Number.isFinite(time) && time >= oneHourAgo;
    });

    const source = recent.length ? recent : alertRows.slice(0, 50);

    const agentSet = new Set(source.map(getAgent).filter((a) => a && a !== "-"));
    const highSeverity = source.filter((a) => getRuleLevel(a) >= 10).length;
    const timeRange = formatTimeRange(source);

    const openInvestigations = incidentRows.filter((incident) =>
      String(incident.status || "").toLowerCase().includes("investigation")
    ).length;

    const countText = source.length;
    const agentText = agentSet.size;

    return `${countText} alerts fired${timeRange ? ` in the selected window (${timeRange})` : ""} across ${agentText} agents. ${highSeverity} high-severity alerts (level ≥ 10) were observed. There are ${openInvestigations} active investigation incidents. The environment activity is summarized below from live Wazuh and incident data.`;
  }

  const handleAsk = () => {
  setAsking(true);

  setTimeout(() => {
    const q = query.toLowerCase();

    const latestAlerts =
      alerts.length > 0
        ? [...alerts].sort(
            (a, b) =>
              new Date(b.timestamp || b.createdAt) -
              new Date(a.timestamp || a.createdAt)
          )
        : [];

    if (
      q.includes("last hour") ||
      q.includes("1 hour") ||
      q.includes("one hour")
    ) {
      setAnswer(buildAnswer(alerts, incidents));
    }

    else if (
      q.includes("high") ||
      q.includes("critical")
    ) {
      const high = latestAlerts.filter(
        a => getRuleLevel(a) >= 10
      );

      setAnswer(
        `${high.length} high severity alerts found. ` +
        high
          .slice(0,5)
          .map(
            a =>
              `${getRule(a)} on ${getAgent(a)}`
          )
          .join(", ")
      );
    }

    else if (
      q.includes("user")
    ) {
      const users = [
        ...new Set(
          latestAlerts
            .map(a=>a.user)
            .filter(Boolean)
        )
      ];

      setAnswer(
        `Observed users: ${users.slice(0,10).join(", ")}`
      );
    }

    else if (
      q.includes("agent")
    ) {
      const agents = [
        ...new Set(
          latestAlerts
            .map(getAgent)
            .filter(Boolean)
        )
      ];

      setAnswer(
        `Active agents: ${agents.join(", ")}`
      );
    }

    else {
      setAnswer(buildAnswer(alerts, incidents));
    }

    setAsking(false);

  },300);
};

  return (
    <SiemLayout>
      <div className="investigate-page">
        <div className="investigate-header">
          <h1>Investigate</h1>
          <p>Ask questions about your environment in plain English.</p>
        </div>

        <div className="ask-row">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Ask about Wazuh alerts, incidents, users, agents, or rules..."
          />
          <button onClick={handleAsk} disabled={asking || loading}>
            {asking ? "Asking..." : "Ask"}
          </button>
        </div>

        <div className="answer-card">
          <h2>Answer</h2>

          {loading ? (
            <p className="answer-text">Loading live Wazuh investigation data...</p>
          ) : (
            <p className="answer-text">{answer}</p>
          )}

          <h3>Alert Summary by Rule</h3>

          <div className="summary-table-wrap">
            <table className="summary-table">
              <thead>
                <tr>
                  <th>Rule ID</th>
                  <th>Description</th>
                  <th>Level</th>
                  <th>Count</th>
                  <th>Agent(s)</th>
                </tr>
              </thead>

              <tbody>
                {summaryRows.length === 0 ? (
                  <tr>
                    <td colSpan="5">No live Wazuh alert data found.</td>
                  </tr>
                ) : (
                  summaryRows.map((row) => (
                    <tr key={`${row.ruleId}-${row.description}`}>
                      <td>{row.ruleId}</td>
                      <td>{row.description}</td>
                      <td>{row.level}</td>
                      <td>{row.count}</td>
                      <td>{row.agents}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </SiemLayout>
  );
}