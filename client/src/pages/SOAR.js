import React, { useEffect, useMemo, useState } from "react";
import SiemLayout from "../components/siem/SiemLayout";
import "../styles/SOAR.css";

const API_BASE = "http://10.0.3.83:5000";

export default function SOAR() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState("");

  const getArray = (payload) => {
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.data)) return payload.data;
    if (Array.isArray(payload?.incidents)) return payload.incidents;
    return [];
  };

  const safeNumber = (value, fallback = 0) => {
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
  };

  const formatConfidence = (value) => {
    const number = safeNumber(value);
    if (number <= 1) return `${Math.round(number * 100)}%`;
    return `${Math.round(number)}%`;
  };

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

  const loadSOAR = async () => {
    try {
      setLoading(true);

      const res = await fetch(`${API_BASE}/api/incidents?limit=300`);
      const data = await res.json();

      setIncidents(getArray(data));
    } catch (err) {
      console.error("SOAR fetch error:", err);
      setIncidents([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSOAR();

    const interval = setInterval(loadSOAR, 180000);
    return () => clearInterval(interval);
  }, []);

  const inferActionType = (text = "") => {
    const value = text.toLowerCase();

    if (value.includes("isolate")) return "isolate_host";
    if (value.includes("block") && value.includes("ip")) return "block_ip";
    if (value.includes("disable") && value.includes("user")) return "disable_user";
    if (value.includes("kill") && value.includes("process")) return "kill_process";
    if (value.includes("ticket")) return "create_ticket";
    if (value.includes("credential") || value.includes("reset")) return "reset_credentials";
    if (value.includes("contain")) return "containment";
    if (value.includes("investigat")) return "investigation";
    return "manual_review";
  };

  const inferTarget = (incident = {}, playbook = {}) => {
    const actionText = `${playbook.title || ""} ${playbook.action || ""} ${
      playbook.description || ""
    }`.toLowerCase();

    if (actionText.includes("host") || actionText.includes("isolate")) {
      return incident.host || incident.agentId || incident.agent || "";
    }

    if (actionText.includes("user") || actionText.includes("credential")) {
      return Array.isArray(incident.users) && incident.users.length ? incident.users[0] : "";
    }

    if (actionText.includes("ip") || actionText.includes("network")) {
      return Array.isArray(incident.networkConnections) && incident.networkConnections.length
        ? incident.networkConnections[0]
        : incident.ip || "";
    }

    if (actionText.includes("process")) {
      return Array.isArray(incident.processes) && incident.processes.length
        ? incident.processes[0]
        : "";
    }

    return incident.host || incident.incidentKey || "";
  };

  const actions = useMemo(() => {
    return incidents.flatMap((incident) => {
      const playbooks = Array.isArray(incident.playbooks) ? incident.playbooks : [];
      const soarActions = Array.isArray(incident.soarActions) ? incident.soarActions : [];

      const playbookActions = playbooks.map((playbook, index) => {
        const actionText = `${playbook.title || ""} ${playbook.action || ""} ${
          playbook.description || ""
        }`;
        const actionType = playbook.actionType || inferActionType(actionText);
        const target = playbook.target || inferTarget(incident, playbook);

        return {
          id: `${incident._id || incident.incidentKey}-playbook-${index}`,
          source: "playbook",
          incidentKey: incident.incidentKey,
          title: playbook.title || playbook.name || playbook.action || "SOAR Playbook",
          action: playbook.action || playbook.description || incident.recommendedAction || "-",
          actionType,
          target,
          status: playbook.status || "pending",
          approvalRequired:
            playbook.approval_required === true ||
            playbook.approvalRequired === true ||
            playbook.status === "approval_required",
          enabled: playbook.enabled !== false,
          steps: Array.isArray(playbook.steps)
            ? playbook.steps.length
            : safeNumber(playbook.steps || playbook.actionCount || playbook.actions, 1),
          host: incident.host || incident.agent || "-",
          severity: incident.severity || "-",
          priority: incident.priority || "-",
          tier: incident.tier || "-",
          risk: safeNumber(incident.riskScore || incident.risk || 0),
          verdict: incident.verdict || "-",
          confidence: safeNumber(incident.aiConfidence || incident.confidence || 0),
          incidentTitle: incident.title || "-",
          recommendedAction: incident.recommendedAction || "-",
          escalationStatus: incident.escalationStatus || "-",
          requiresHumanReview: incident.requiresHumanReview === true,
          createdAt: playbook.createdAt || incident.createdAt || incident.lastSeen || "-",
          analyst: playbook.analyst || incident.analyst || "system",
          mitreTechniques: Array.isArray(incident.mitreTechniques) ? incident.mitreTechniques : [],
          raw: { incident, playbook },
        };
      });

      const queuedActions = soarActions.map((action, index) => ({
        id: `${incident._id || incident.incidentKey}-queued-${index}`,
        source: "queued",
        incidentKey: incident.incidentKey,
        title: action.title || action.action || "SOAR Action",
        action: action.result || action.action || "-",
        actionType: action.actionType || action.action || "manual_review",
        target: action.target || "",
        status: action.status || "queued",
        approvalRequired: action.approval_required === true || action.approvalRequired === true,
        enabled: action.enabled !== false,
        steps: Array.isArray(action.steps)
          ? action.steps.length
          : safeNumber(action.steps || action.stepCount, 1),
        host: incident.host || "-",
        severity: incident.severity || "-",
        priority: incident.priority || "-",
        tier: incident.tier || "-",
        risk: safeNumber(incident.riskScore || incident.risk || 0),
        verdict: incident.verdict || "-",
        confidence: safeNumber(incident.aiConfidence || incident.confidence || 0),
        incidentTitle: incident.title || "-",
        recommendedAction: incident.recommendedAction || "-",
        escalationStatus: incident.escalationStatus || "-",
        requiresHumanReview: incident.requiresHumanReview === true,
        createdAt: action.requested_at || action.createdAt || incident.createdAt || incident.lastSeen || "-",
        analyst: action.analyst || "system",
        mitreTechniques: Array.isArray(incident.mitreTechniques) ? incident.mitreTechniques : [],
        raw: { incident, action },
      }));

      return [...playbookActions, ...queuedActions];
    });
  }, [incidents]);

  const queueAction = async (item) => {
    try {
      setActionLoading(item.id);

      const res = await fetch(`${API_BASE}/api/incidents/${item.incidentKey}/soar-action`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          action: item.actionType,
          target: item.target,
          analyst: "shruthi",
          approval_required: item.approvalRequired,
          status: item.approvalRequired ? "approval_required" : "queued",
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        console.error("SOAR queue failed:", data);
        alert("SOAR action failed. Check backend.");
        return;
      }

      await loadSOAR();
    } catch (err) {
      console.error("SOAR action error:", err);
      alert("SOAR action failed. Backend not reachable.");
    } finally {
      setActionLoading("");
    }
  };

  const pendingApprovals = useMemo(() => {
    return actions.filter((item) => item.approvalRequired || item.status === "approval_required");
  }, [actions]);

  const playbooks = useMemo(() => {
    return actions.filter((item) => item.source === "playbook");
  }, [actions]);

  const executionBoard = useMemo(() => {
    return {
      pending: actions.filter((item) => item.status === "pending"),
      running: actions.filter((item) => item.status === "running"),
      completed: actions.filter(
        (item) =>
          item.status === "completed" ||
          item.status === "success" ||
          item.status === "done" ||
          item.status === "executed"
      ),
      failed: actions.filter((item) => item.status === "failed" || item.status === "error"),
    };
  }, [actions]);

  const stats = useMemo(() => {
    const completed = executionBoard.completed.length;
    const failed = executionBoard.failed.length;
    const finished = completed + failed;

    return {
      activePlaybooks: playbooks.filter((item) => item.enabled).length,
      pendingApprovals: pendingApprovals.length,
      executionsToday: actions.filter((item) => {
        const date = new Date(item.createdAt);
        if (Number.isNaN(date.getTime())) return false;
        const today = new Date();
        return date.toDateString() === today.toDateString();
      }).length,
      successRate: finished ? Math.round((completed / finished) * 100) : 100,
    };
  }, [actions, playbooks, pendingApprovals, executionBoard]);

  return (
    <SiemLayout>
      <div className="soar-page">
        <div className="soar-header">
          <h1>SOAR Playbooks</h1>
          <p>Automated response orchestration — playbooks evaluate on every true positive triage decision.</p>
        </div>

        <div className="soar-stats">
          <div>
            <h2>{loading ? "..." : stats.activePlaybooks}</h2>
            <p>Active Playbooks</p>
          </div>

          <div>
            <h2>{loading ? "..." : stats.pendingApprovals}</h2>
            <p>Pending Approvals</p>
          </div>

          <div>
            <h2>{loading ? "..." : stats.executionsToday}</h2>
            <p>Executions Today</p>
          </div>

          <div>
            <h2>{loading ? "..." : `${stats.successRate}%`}</h2>
            <p>Success Rate</p>
          </div>
        </div>

        <section className="soar-section-block">
          <h2>Pending Approvals</h2>

          {loading ? (
            <div className="soar-empty light">Loading approvals...</div>
          ) : pendingApprovals.length === 0 ? (
            <div className="soar-empty light">No pending approvals.</div>
          ) : (
            pendingApprovals.slice(0, 1).map((item) => (
              <div className="approval-banner" key={item.id}>
                <div>
                  <h3>
                    {item.title} <span>{item.incidentKey}</span>
                  </h3>

                  <p>
                    Triggered because alert matched: confidence{" "}
                    <b>{formatConfidence(item.confidence)}</b>, risk{" "}
                    <b>{item.risk}/100</b>
                    {item.mitreTechniques.length > 0 && (
                      <>
                        , MITRE <b>{item.mitreTechniques.join(" ")}</b>
                      </>
                    )}
                  </p>

                  <p>
                    Planned actions: <b>{item.actionType}</b>
                    {item.target && <> → {item.target}</>}
                  </p>
                </div>

                <div className="approval-actions">
                  <button
                    className="approve"
                    onClick={() => queueAction(item)}
                    disabled={actionLoading === item.id}
                  >
                    {actionLoading === item.id ? "Approving..." : "Approve"}
                  </button>

                  <button className="reject">Reject</button>
                </div>
              </div>
            ))
          )}
        </section>

        <section className="soar-section-block">
          <h2>Playbooks</h2>

          {loading ? (
            <div className="soar-empty light">Loading playbooks...</div>
          ) : playbooks.length === 0 ? (
            <div className="soar-empty light">No playbooks found.</div>
          ) : (
            <div className="playbook-grid">
              {playbooks.map((item) => (
                <div className="playbook-card" key={item.id}>
                  <div className="playbook-card-top">
                    <h3>{item.title}</h3>
                    <span>{item.enabled ? "Enabled" : "Disabled"}</span>
                  </div>

                  <p>{item.action}</p>

                  <div className="playbook-tags">
                    {item.mitreTechniques.slice(0, 2).map((technique) => (
                      <span key={`${item.id}-${technique}`}>{technique}</span>
                    ))}

                    <span>{item.steps} actions</span>
                  </div>

                  <div className="playbook-footer">
                    {item.approvalRequired && <b>Approval Required</b>}
                    <span>Conf ≥{formatConfidence(item.confidence)}</span>
                    <span>Risk ≥{item.risk}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="execution-section">
          <h2>Execution Board</h2>

          <div className="execution-board">
            {[
              ["Pending", executionBoard.pending],
              ["Running", executionBoard.running],
              ["Completed", executionBoard.completed],
              ["Failed", executionBoard.failed],
            ].map(([label, list]) => (
              <div className="execution-column" key={label}>
                <div className="execution-column-head">
                  <h3>{label}</h3>
                  <span>{list.length}</span>
                </div>

                {list.length === 0 ? (
                  <div className="execution-none">None</div>
                ) : (
                  list.map((item) => (
                    <div className="execution-item" key={`${label}-${item.id}`}>
                      <strong>{item.title}</strong>
                      <p>
                        {formatTime(item.createdAt)} / {item.steps} steps by {item.analyst}
                      </p>

                      {(label === "Completed" || label === "Failed") && (
                        <button>Rollback</button>
                      )}
                    </div>
                  ))
                )}
              </div>
            ))}
          </div>
        </section>
      </div>
    </SiemLayout>
  );
}