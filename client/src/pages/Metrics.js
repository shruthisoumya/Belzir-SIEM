import React, { useEffect, useMemo, useState } from "react";
import SiemLayout from "../components/siem/SiemLayout";
import "../styles/Metrics.css";

const API_BASE = "http://10.0.3.83:5000";

export default function Metrics() {
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [patterns, setPatterns] = useState([]);
  const [loading, setLoading] = useState(true);

  const getArray = (payload) => {
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

  const minutesBetween = (start, end) => {
    const a = new Date(start || 0).getTime();
    const b = new Date(end || 0).getTime();

    if (!a || !b || Number.isNaN(a) || Number.isNaN(b) || b < a) return null;

    return Math.round((b - a) / 60000);
  };

  const formatDuration = (minutes) => {
    if (minutes === null || minutes === undefined || Number.isNaN(minutes)) return "N/A";
    if (minutes < 60) return `${Math.round(minutes)}m`;

    const hours = minutes / 60;
    if (hours < 24) return `${Number(hours.toFixed(1))}h`;

    return `${Number((hours / 24).toFixed(1))}d`;
  };

  const average = (values) => {
    const valid = values.filter((value) => Number.isFinite(value));
    if (valid.length === 0) return null;
    return valid.reduce((sum, value) => sum + value, 0) / valid.length;
  };

  const getIncidentCreated = (incident) =>
    incident.createdAt ||
    incident.firstSeen ||
    incident.timestamp ||
    incident.lastSeen ||
    incident.updatedAt ||
    "-";

  const getIncidentAcknowledged = (incident) =>
    incident.acknowledgedAt ||
    incident.assignedAt ||
    incident.investigatingAt ||
    incident.updatedAt ||
    incident.lastSeen ||
    "-";

  const getIncidentResolved = (incident) =>
    incident.resolvedAt ||
    incident.closedAt ||
    incident.completedAt ||
    incident.statusUpdatedAt ||
    "-";

  useEffect(() => {
    let cancelled = false;

    async function loadMetrics() {
      try {
        setLoading(true);

        const [alertsRes, incidentsRes, patternsRes] = await Promise.all([
          fetch(`${API_BASE}/api/wazuh/mitre-lite?limit=500`),
          fetch(`${API_BASE}/api/incidents?limit=300`),
          fetch(`${API_BASE}/api/wazuh/alert-patterns?limit=500`),
        ]);

        const [alertsData, incidentsData, patternsData] = await Promise.all([
          alertsRes.json(),
          incidentsRes.json(),
          patternsRes.json(),
        ]);

        if (cancelled) return;

        setAlerts(getArray(alertsData));
        setIncidents(getArray(incidentsData));
        setPatterns(getArray(patternsData));
      } catch (err) {
        console.error("Metrics fetch error:", err);
        setAlerts([]);
        setIncidents([]);
        setPatterns([]);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    loadMetrics();

    const interval = setInterval(loadMetrics, 180000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const thirtyDayIncidents = useMemo(() => {
    const now = Date.now();
    const cutoff = now - 30 * 24 * 60 * 60 * 1000;

    return incidents.filter((incident) => {
      const time = new Date(getIncidentCreated(incident)).getTime();
      return Number.isFinite(time) && time >= cutoff;
    });
  }, [incidents]);

  const severityRows = useMemo(() => {
    const severities = ["Critical", "High", "Medium", "Low"];

    return severities.map((severity) => {
      const list = thirtyDayIncidents.filter(
        (incident) => String(incident.severity || "").toLowerCase() === severity.toLowerCase()
      );

      const mttd = average(
        list.map((incident) =>
          minutesBetween(getIncidentCreated(incident), incident.lastSeen || incident.updatedAt)
        )
      );

      const mtta = average(
        list.map((incident) =>
          minutesBetween(getIncidentCreated(incident), getIncidentAcknowledged(incident))
        )
      );

      const mttr = average(
        list
          .filter((incident) =>
            ["resolved", "closed", "completed"].includes(
              String(incident.status || "").toLowerCase()
            )
          )
          .map((incident) =>
            minutesBetween(getIncidentCreated(incident), getIncidentResolved(incident))
          )
      );

      return {
        severity,
        count: list.length,
        mttd,
        mtta,
        mttr,
      };
    });
  }, [thirtyDayIncidents]);

  const analystRows = useMemo(() => {
    const map = new Map();

    thirtyDayIncidents.forEach((incident) => {
      const analyst =
        incident.assigned ||
        incident.assignee ||
        incident.analyst ||
        incident.owner ||
        "admin";

      if (!map.has(analyst)) {
        map.set(analyst, {
          analyst,
          incidentsTouched: 0,
          resolved: 0,
          totalActions: 0,
        });
      }

      const row = map.get(analyst);
      row.incidentsTouched += 1;

      if (
        ["resolved", "closed", "completed"].includes(
          String(incident.status || "").toLowerCase()
        )
      ) {
        row.resolved += 1;
      }

      row.totalActions +=
        safeNumber(incident.timeline?.length) +
        safeNumber(incident.soarActions?.length) +
        safeNumber(incident.playbooks?.length);
    });

    return Array.from(map.values()).sort(
      (a, b) => b.incidentsTouched - a.incidentsTouched
    );
  }, [thirtyDayIncidents]);

  const summary = useMemo(() => {
    const mttd = average(
      thirtyDayIncidents.map((incident) =>
        minutesBetween(getIncidentCreated(incident), incident.lastSeen || incident.updatedAt)
      )
    );

    const mtta = average(
      thirtyDayIncidents.map((incident) =>
        minutesBetween(getIncidentCreated(incident), getIncidentAcknowledged(incident))
      )
    );

    const resolvedIncidents = thirtyDayIncidents.filter((incident) =>
      ["resolved", "closed", "completed"].includes(
        String(incident.status || "").toLowerCase()
      )
    );

    const mttr = average(
      resolvedIncidents.map((incident) =>
        minutesBetween(getIncidentCreated(incident), getIncidentResolved(incident))
      )
    );

    const responseSlaOk = thirtyDayIncidents.filter((incident) => {
      const value = minutesBetween(getIncidentCreated(incident), getIncidentAcknowledged(incident));
      return value !== null && value <= 30;
    }).length;

    const resolutionSlaOk = resolvedIncidents.filter((incident) => {
      const value = minutesBetween(getIncidentCreated(incident), getIncidentResolved(incident));
      return value !== null && value <= 24 * 60;
    }).length;

    return {
      mttd,
      mtta,
      mttr,
      responseSla:
        thirtyDayIncidents.length > 0
          ? Math.round((responseSlaOk / thirtyDayIncidents.length) * 1000) / 10
          : 0,
      resolutionSla:
        resolvedIncidents.length > 0
          ? Math.round((resolutionSlaOk / resolvedIncidents.length) * 1000) / 10
          : 0,
      incidents: thirtyDayIncidents.length,
    };
  }, [thirtyDayIncidents]);

  return (
    <SiemLayout>
      <div className="metrics-page">
        <div className="metrics-header">
          <h1>SOC Metrics</h1>
          <p>
            Operational performance over the last 30 days ({loading ? "..." : summary.incidents} incidents)
          </p>
        </div>

        <div className="metrics-grid">
          <div className="metrics-card blue">
            <h2>{loading ? "..." : formatDuration(summary.mttd)}</h2>
            <strong>MTTD</strong>
            <p>Mean Time to Detect</p>
          </div>

          <div className="metrics-card purple">
            <h2>{loading ? "..." : formatDuration(summary.mtta)}</h2>
            <strong>MTTA</strong>
            <p>Mean Time to Acknowledge</p>
          </div>

          <div className="metrics-card yellow">
            <h2>{loading ? "..." : formatDuration(summary.mttr)}</h2>
            <strong>MTTR</strong>
            <p>Mean Time to Resolve</p>
          </div>

          <div className="metrics-card red">
            <h2>{loading ? "..." : `${summary.responseSla}%`}</h2>
            <strong>SLA Response</strong>
            <p>Response compliance</p>
          </div>

          <div className="metrics-card red">
            <h2>{loading ? "..." : `${summary.resolutionSla}%`}</h2>
            <strong>SLA Resolution</strong>
            <p>Resolution compliance</p>
          </div>

          <div className="metrics-card muted">
            <h2>{loading ? "..." : summary.incidents}</h2>
            <strong>Incidents</strong>
            <p>30-day total</p>
          </div>
        </div>

        <section className="metrics-table-section">
          <h2>By Severity</h2>

          <div className="metrics-table">
            <div className="metrics-table-head">
              <span>Severity</span>
              <span>Count</span>
              <span>MTTD</span>
              <span>MTTA</span>
              <span>MTTR</span>
            </div>

            {severityRows.map((row) => (
              <div className="metrics-table-row" key={row.severity}>
                <span className={`severity-chip ${row.severity.toLowerCase()}`}>
                  {row.severity}
                </span>
                <span>{loading ? "..." : row.count}</span>
                <span>{loading ? "..." : formatDuration(row.mttd)}</span>
                <span>{loading ? "..." : formatDuration(row.mtta)}</span>
                <span>{loading ? "..." : formatDuration(row.mttr)}</span>
              </div>
            ))}
          </div>
        </section>

        <section className="metrics-table-section">
          <h2>Analyst Performance (30d)</h2>

          <div className="metrics-table analyst-table">
            <div className="metrics-table-head">
              <span>Analyst</span>
              <span>Incidents Touched</span>
              <span>Resolved</span>
              <span>Total Actions</span>
            </div>

            {loading ? (
              <div className="metrics-empty">Loading analyst performance...</div>
            ) : analystRows.length === 0 ? (
              <div className="metrics-empty">No analyst activity found.</div>
            ) : (
              analystRows.map((row) => (
                <div className="metrics-table-row" key={row.analyst}>
                  <strong>{row.analyst}</strong>
                  <span>{row.incidentsTouched}</span>
                  <span>{row.resolved}</span>
                  <span>{row.totalActions}</span>
                </div>
              ))
            )}
          </div>
        </section>
      </div>
    </SiemLayout>
  );
}