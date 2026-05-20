import React, { useEffect, useMemo, useState } from "react";
import SiemLayout from "../components/siem/SiemLayout";
import "../styles/Respond.css";

const API_BASE = "http://10.0.3.83:5000";

export default function Respond() {
  const [incidents, setIncidents] = useState([]);
  const [agents, setAgents] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState("");

  const getArray = (payload) => {
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.data)) return payload.data;
    if (Array.isArray(payload?.incidents)) return payload.incidents;
    if (Array.isArray(payload?.agents)) return payload.agents;
    if (Array.isArray(payload?.vulnerabilities)) return payload.vulnerabilities;
    if (Array.isArray(payload?.items)) return payload.items;
    return [];
  };

  const safeNumber = (value, fallback = 0) => {
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
  };

  const normalizeText = (value) =>
    String(value || "")
      .toLowerCase()
      .trim();

  const titleCase = (value) =>
    String(value || "")
      .replace(/_/g, " ")
      .replace(/-/g, " ")
      .trim()
      .replace(/\w\S*/g, (text) => text.charAt(0).toUpperCase() + text.slice(1).toLowerCase());

  const actionIcon = (action) => {
    const value = normalizeText(action);

    if (value.includes("block")) return "🚫";
    if (value.includes("unblock")) return "✅";
    if (value.includes("isolate")) return "🔒";
    if (value.includes("unisolate")) return "🔓";
    if (value.includes("kill")) return "☠️";
    if (value.includes("disable")) return "🚷";
    if (value.includes("enable")) return "👤";
    if (value.includes("quarantine")) return "📦";
    if (value.includes("restart")) return "🔄";

    return "⚡";
  };

  const actionTone = (action) => {
    const value = normalizeText(action);

    if (
      value.includes("block") ||
      value.includes("isolate") ||
      value.includes("kill") ||
      value.includes("disable")
    ) {
      return "danger";
    }

    if (
      value.includes("unblock") ||
      value.includes("unisolate") ||
      value.includes("enable") ||
      value.includes("restart")
    ) {
      return "success";
    }

    if (value.includes("quarantine")) return "warning";

    return "neutral";
  };

  const actionSubtitle = (action) => {
    const value = normalizeText(action);

    if (value.includes("block_ip")) return "Firewall drop";
    if (value.includes("unblock_ip")) return "Remove firewall block";
    if (value.includes("isolate_host")) return "Network isolation";
    if (value.includes("unisolate_host")) return "Remove isolation";
    if (value.includes("kill_process")) return "Terminate by PID";
    if (value.includes("disable_user")) return "Lock account";
    if (value.includes("enable_user")) return "Unlock account";
    if (value.includes("quarantine_file")) return "Isolate malicious file";
    if (value.includes("restart_agent")) return "Restart Wazuh agent";

    return "Response action";
  };

  const inferTarget = (incident, actionType) => {
    const value = normalizeText(actionType);

    if (value.includes("ip")) {
      if (incident.ip) return incident.ip;
      if (Array.isArray(incident.sourceIPs) && incident.sourceIPs.length) return incident.sourceIPs[0];
      if (Array.isArray(incident.destinationIPs) && incident.destinationIPs.length) {
        return incident.destinationIPs[0];
      }
    }

    if (value.includes("host") || value.includes("agent") || value.includes("isolate")) {
      return incident.host || incident.agent || incident.agentName || incident.agentId || "";
    }

    if (value.includes("user")) {
      return Array.isArray(incident.users) && incident.users.length ? incident.users[0] : "";
    }

    if (value.includes("process")) {
      return Array.isArray(incident.processes) && incident.processes.length
        ? incident.processes[0]
        : "";
    }

    if (value.includes("file")) {
      return Array.isArray(incident.files) && incident.files.length ? incident.files[0] : "";
    }

    return incident.host || incident.incidentKey || "";
  };

  async function loadRespondData() {
    try {
      setLoading(true);

      const [incidentsRes, agentsRes, vulnRes] = await Promise.allSettled([
        fetch(`${API_BASE}/api/incidents?limit=300`),
        fetch(`${API_BASE}/api/wazuh/agents?limit=300`),
        fetch(`${API_BASE}/api/wazuh/vulnerabilities?limit=300`),
      ]);

      if (incidentsRes.status === "fulfilled") {
        const data = await incidentsRes.value.json();
        setIncidents(getArray(data));
      }

      if (agentsRes.status === "fulfilled" && agentsRes.value.ok) {
        const data = await agentsRes.value.json();
        setAgents(getArray(data));
      }

      if (vulnRes.status === "fulfilled" && vulnRes.value.ok) {
        const data = await vulnRes.value.json();
        setVulnerabilities(getArray(data));
      }
    } catch (err) {
      console.error("Respond fetch error:", err);
      setIncidents([]);
      setAgents([]);
      setVulnerabilities([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadRespondData();

    const interval = setInterval(loadRespondData, 180000);
    return () => clearInterval(interval);
  }, []);

  const responseActions = useMemo(() => {
    const map = new Map();

    incidents.forEach((incident) => {
      const playbooks = Array.isArray(incident.playbooks) ? incident.playbooks : [];
      const soarActions = Array.isArray(incident.soarActions) ? incident.soarActions : [];

      playbooks.forEach((playbook) => {
        const type =
          playbook.actionType ||
          playbook.action ||
          playbook.type ||
          playbook.name ||
          playbook.title ||
          "";

        if (!type) return;

        const key = normalizeText(type).replace(/\s+/g, "_");

        if (!map.has(key)) {
          map.set(key, {
            key,
            title: titleCase(key),
            subtitle: actionSubtitle(key),
            icon: actionIcon(key),
            tone: actionTone(key),
            count: 0,
            incidents: [],
          });
        }

        const item = map.get(key);
        item.count += 1;
        item.incidents.push(incident);
      });

      soarActions.forEach((action) => {
        const type = action.actionType || action.action || action.type || "";

        if (!type) return;

        const key = normalizeText(type).replace(/\s+/g, "_");

        if (!map.has(key)) {
          map.set(key, {
            key,
            title: titleCase(key),
            subtitle: actionSubtitle(key),
            icon: actionIcon(key),
            tone: actionTone(key),
            count: 0,
            incidents: [],
          });
        }

        const item = map.get(key);
        item.count += 1;
        item.incidents.push(incident);
      });
    });

    return Array.from(map.values()).sort((a, b) => b.count - a.count);
  }, [incidents]);

  const vulnerabilityRows = useMemo(() => {
    const rowsFromEndpoint = vulnerabilities.map((item, index) => ({
      id: item.id || item._id || item.cve || `vuln-${index}`,
      cve: item.cve || item.cveId || item.name || "-",
      severity: item.severity || item.cvssSeverity || "unknown",
      agent:
        item.agent ||
        item.agentName ||
        item.host ||
        item.hostname ||
        item.agent_id ||
        item.agentId ||
        "-",
      count: safeNumber(item.count || item.occurrences || 1, 1),
    }));

    if (rowsFromEndpoint.length > 0) return rowsFromEndpoint;

    return incidents.flatMap((incident, index) => {
      const cves = [
        ...(Array.isArray(incident.cves) ? incident.cves : []),
        ...(Array.isArray(incident.vulnerabilities) ? incident.vulnerabilities : []),
      ];

      return cves.map((cve, cveIndex) => ({
        id: `${incident._id || incident.incidentKey || index}-${cveIndex}`,
        cve: typeof cve === "string" ? cve : cve.cve || cve.cveId || cve.name || "-",
        severity:
          typeof cve === "object"
            ? cve.severity || cve.cvssSeverity || incident.severity || "unknown"
            : incident.severity || "unknown",
        agent: incident.host || incident.agent || "-",
        count: 1,
      }));
    });
  }, [vulnerabilities, incidents]);

  const vulnSummary = useMemo(() => {
    const affectedAgents = new Set(
      vulnerabilityRows.map((item) => item.agent).filter((item) => item && item !== "-")
    );

    return {
      total: vulnerabilityRows.reduce((sum, item) => sum + item.count, 0),
      affectedAgents: affectedAgents.size || agents.length,
      critical: vulnerabilityRows
        .filter((item) => normalizeText(item.severity).includes("critical"))
        .reduce((sum, item) => sum + item.count, 0),
      high: vulnerabilityRows
        .filter((item) => normalizeText(item.severity).includes("high"))
        .reduce((sum, item) => sum + item.count, 0),
      medium: vulnerabilityRows
        .filter((item) => normalizeText(item.severity).includes("medium"))
        .reduce((sum, item) => sum + item.count, 0),
      low: vulnerabilityRows
        .filter((item) => normalizeText(item.severity).includes("low"))
        .reduce((sum, item) => sum + item.count, 0),
    };
  }, [vulnerabilityRows, agents]);

  const topCves = useMemo(() => {
    const map = new Map();

    vulnerabilityRows.forEach((item) => {
      if (!item.cve || item.cve === "-") return;
      map.set(item.cve, (map.get(item.cve) || 0) + item.count);
    });

    return Array.from(map.entries())
      .map(([cve, count]) => ({ cve, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }, [vulnerabilityRows]);

  const executeResponse = async (action) => {
    const incident = action.incidents[0];

    if (!incident?.incidentKey) return;

    try {
      setActionLoading(action.key);

      const res = await fetch(`${API_BASE}/api/incidents/${incident.incidentKey}/soar-action`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          action: action.key,
          target: inferTarget(incident, action.key),
          analyst: "shruthi",
          approval_required: true,
          status: "approval_required",
        }),
      });

      if (!res.ok) {
        const data = await res.json();
        console.error("Response action failed:", data);
        alert("Response action failed. Check backend.");
        return;
      }

      await loadRespondData();
    } catch (err) {
      console.error("Response action error:", err);
      alert("Response action failed. Backend not reachable.");
    } finally {
      setActionLoading("");
    }
  };

  return (
    <SiemLayout>
      <div className="respond-page">
        <section className="respond-section">
          <h2>ACTIVE RESPONSE ACTIONS</h2>

          {loading ? (
            <div className="respond-empty">Loading response actions...</div>
          ) : responseActions.length === 0 ? (
            <div className="respond-empty">No response actions found from live incidents.</div>
          ) : (
            <div className="response-actions-grid">
              {responseActions.map((action) => (
                <button
                  key={action.key}
                  className={`response-action-card ${action.tone}`}
                  onClick={() => executeResponse(action)}
                  disabled={actionLoading === action.key}
                >
                  <div className="response-action-icon">{action.icon}</div>
                  <h3>{action.title}</h3>
                  <p>{action.subtitle}</p>
                  <span>{action.count}</span>
                </button>
              ))}
            </div>
          )}
        </section>

        <section className="respond-section">
          <h2>VULNERABILITY OVERVIEW</h2>

          <div className="vuln-overview-grid">
            <div className="vuln-card">
              <p>Total Vulnerabilities</p>
              <h3>{loading ? "..." : vulnSummary.total.toLocaleString("en-US")}</h3>
            </div>

            <div className="vuln-card blue">
              <p>Affected Agents</p>
              <h3>{loading ? "..." : vulnSummary.affectedAgents.toLocaleString("en-US")}</h3>
            </div>

            <div className="vuln-card critical">
              <p>Critical</p>
              <h3>{loading ? "..." : vulnSummary.critical.toLocaleString("en-US")}</h3>
            </div>

            <div className="vuln-card high">
              <p>High</p>
              <h3>{loading ? "..." : vulnSummary.high.toLocaleString("en-US")}</h3>
            </div>

            <div className="vuln-card medium">
              <p>Medium</p>
              <h3>{loading ? "..." : vulnSummary.medium.toLocaleString("en-US")}</h3>
            </div>

            <div className="vuln-card low">
              <p>Low</p>
              <h3>{loading ? "..." : vulnSummary.low.toLocaleString("en-US")}</h3>
            </div>
          </div>
        </section>

        <section className="top-cve-panel">
          <h2>TOP CVES</h2>

          <div className="top-cve-table">
            <div className="top-cve-head">
              <span>CVE</span>
              <span>Count</span>
            </div>

            {loading ? (
              <div className="respond-empty table-empty">Loading CVEs...</div>
            ) : topCves.length === 0 ? (
              <div className="respond-empty table-empty">No CVEs found from live data.</div>
            ) : (
              topCves.map((item) => (
                <div className="top-cve-row" key={item.cve}>
                  <strong>{item.cve}</strong>
                  <span>{item.count.toLocaleString("en-US")}</span>
                </div>
              ))
            )}
          </div>
        </section>
      </div>
    </SiemLayout>
  );
}