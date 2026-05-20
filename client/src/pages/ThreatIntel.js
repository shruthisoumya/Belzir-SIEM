import React, { useEffect, useMemo, useState } from "react";
import SiemLayout from "../components/siem/SiemLayout";
import "../styles/ThreatIntel.css";

const API_BASE = "http://10.0.3.83:5000";

export default function ThreatIntel() {
  const [items, setItems] = useState([]);
  const [summary, setSummary] = useState({});
  const [feedSummary, setFeedSummary] = useState([]);
  const [loading, setLoading] = useState(true);

  const getArray = (payload) => {
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.data)) return payload.data;
    if (Array.isArray(payload?.incidents)) return payload.incidents;
    if (Array.isArray(payload?.items)) return payload.items;
    if (Array.isArray(payload?.iocs)) return payload.iocs;
    if (Array.isArray(payload?.feeds)) return payload.feeds;
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

  const formatNumber = (value) => safeNumber(value).toLocaleString("en-US");

  const formatTime = (value) => {
    if (!value || value === "-") return "—";
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

  const normalizeItem = (incident, index) => {
    const evidence = Array.isArray(incident.evidence) ? incident.evidence : [];
    const first = evidence[0] || {};

    const indicators = [
      ...normalizeArray(incident.indicators),
      ...normalizeArray(first.network_indicators),
      ...normalizeArray(incident.maliciousIPs),
      ...normalizeArray(incident.maliciousHashes),
      ...normalizeArray(incident.suspiciousDomains),
      ...normalizeArray(incident.domains),
      ...normalizeArray(incident.urls),
      ...normalizeArray(incident.hashes),
    ];

    const feedHits = normalizeArray(incident.threatFeedHits || first.threatFeedHits);

    return {
      id: incident.incidentKey || incident._id || `intel-${index}`,
      type:
        incident.iocType ||
        first.ioc_type ||
        (incident.urls?.length ? "url" : "") ||
        (incident.domains?.length ? "domain" : "") ||
        (incident.hashes?.length ? "hash_sha256" : "") ||
        (incident.maliciousIPs?.length ? "ip" : "") ||
        "indicator",
      severity: incident.severity || first.severity || "Medium",
      source:
        incident.source ||
        incident.feed ||
        first.source ||
        first.feed ||
        (feedHits[0]?.source || feedHits[0]?.feed) ||
        "internal",
      feedStatus: incident.feedStatus || "active",
      tier: incident.tier || "Free",
      iocs: indicators,
      iocCount: indicators.length || safeNumber(incident.iocCount || first.iocCount, 1),
      lastFetch: incident.lastFetch || incident.updatedAt || incident.lastSeen || incident.createdAt || "-",
      interval: incident.interval || incident.collectionInterval || "-",
      error: incident.error || incident.lastError || "—",
      raw: incident,
    };
  };

  async function loadThreatIntel() {
    try {
      setLoading(true);

      const res = await fetch(`${API_BASE}/api/incidents/threat-intel?limit=500`);
      const data = await res.json();

      const list = getArray(data).map(normalizeItem);

      setItems(list);
      setSummary(data.summary || {});
      setFeedSummary(getArray(data.feeds || data.feedSummary || data.sources));
    } catch (err) {
      console.error("Threat intel fetch error:", err);
      setItems([]);
      setSummary({});
      setFeedSummary([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadThreatIntel();
    const interval = setInterval(loadThreatIntel, 180000);
    return () => clearInterval(interval);
  }, []);

  const iocTypeRows = useMemo(() => {
    const map = new Map();

    items.forEach((item) => {
      const key = item.type || "indicator";
      map.set(key, (map.get(key) || 0) + item.iocCount);
    });

    return Array.from(map.entries())
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count);
  }, [items]);

  const severityRows = useMemo(() => {
    const map = new Map();

    items.forEach((item) => {
      const key = String(item.severity || "medium").toUpperCase();
      map.set(key, (map.get(key) || 0) + item.iocCount);
    });

    return Array.from(map.entries())
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count);
  }, [items]);

  const sourceRows = useMemo(() => {
    const map = new Map();

    items.forEach((item) => {
      const key = String(item.source || "internal").toLowerCase();
      map.set(key, (map.get(key) || 0) + item.iocCount);
    });

    return Array.from(map.entries())
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count);
  }, [items]);

  const feeds = useMemo(() => {
    if (feedSummary.length > 0) {
      return feedSummary.map((feed, index) => ({
        id: feed.id || feed.name || `feed-${index}`,
        name: feed.name || feed.feed || feed.source || `feed-${index + 1}`,
        tier: feed.tier || "Free",
        status: feed.status || feed.feedStatus || "active",
        iocs: safeNumber(feed.iocs || feed.iocCount || feed.count),
        lastFetch: feed.lastFetch || feed.updatedAt || feed.last_seen || feed.lastSeen || "-",
        interval: feed.interval || feed.collectionInterval || "-",
        error: feed.error || feed.lastError || "—",
      }));
    }

    return sourceRows.map((source, index) => ({
      id: source.name || `source-${index}`,
      name: source.name,
      tier: "Free",
      status: "active",
      iocs: source.count,
      lastFetch: items.find((item) => String(item.source).toLowerCase() === source.name)?.lastFetch || "-",
      interval: "-",
      error: "—",
    }));
  }, [feedSummary, sourceRows, items]);

  const stats = useMemo(() => {
    const totalIocs =
      safeNumber(summary.totalIocs || summary.totalIOCs || summary.indicators) ||
      items.reduce((sum, item) => sum + item.iocCount, 0);

    return {
      totalIocs,
      activeFeeds: feeds.filter((feed) => String(feed.status).toLowerCase() === "active").length,
      sources: sourceRows.length,
      cisaKev:
        safeNumber(summary.cisaKev || summary.cisaKEV || summary.cisaKevCves) ||
        sourceRows.find((source) => source.name.includes("cisa"))?.count ||
        0,
    };
  }, [summary, items, feeds, sourceRows]);

  const maxType = Math.max(...iocTypeRows.map((row) => row.count), 1);
  const maxSeverity = Math.max(...severityRows.map((row) => row.count), 1);

  return (
    <SiemLayout>
      <div className="threat-page">
        <div className="threat-summary-grid">
          <div className="threat-summary-card">
            <h2>{loading ? "..." : formatNumber(stats.totalIocs)}</h2>
            <p>Total IOCs</p>
          </div>

          <div className="threat-summary-card blue">
            <h2>{loading ? "..." : `${stats.activeFeeds}/${feeds.length}`}</h2>
            <p>Active Feeds</p>
          </div>

          <div className="threat-summary-card yellow">
            <h2>{loading ? "..." : formatNumber(stats.sources)}</h2>
            <p>Sources</p>
          </div>

          <div className="threat-summary-card red">
            <h2>{loading ? "..." : formatNumber(stats.cisaKev)}</h2>
            <p>CISA KEV CVEs</p>
          </div>
        </div>

        <div className="threat-chart-grid">
          <div className="threat-panel">
            <h3>IOCS BY TYPE</h3>

            {iocTypeRows.length === 0 ? (
              <div className="threat-empty light">No IOC type data found.</div>
            ) : (
              iocTypeRows.map((row, index) => (
                <div className="bar-row" key={row.name}>
                  <span className={`type-color-${index % 8}`}>{row.name}</span>
                  <div className="bar-track">
                    <div
                      className={`bar-fill type-${index % 8}`}
                      style={{ width: `${Math.max((row.count / maxType) * 100, 1)}%` }}
                    />
                  </div>
                  <strong>{formatNumber(row.count)}</strong>
                </div>
              ))
            )}
          </div>

          <div className="threat-panel">
            <h3>IOCS BY SEVERITY</h3>

            {severityRows.length === 0 ? (
              <div className="threat-empty light">No severity data found.</div>
            ) : (
              severityRows.map((row) => (
                <div className="bar-row" key={row.name}>
                  <span className={`severity-label ${row.name.toLowerCase()}`}>{row.name}</span>
                  <div className="bar-track">
                    <div
                      className={`bar-fill severity-${row.name.toLowerCase()}`}
                      style={{ width: `${Math.max((row.count / maxSeverity) * 100, 1)}%` }}
                    />
                  </div>
                  <strong>{formatNumber(row.count)}</strong>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="threat-panel source-panel">
          <h3>IOCS BY SOURCE</h3>

          <div className="source-chip-grid">
            {sourceRows.length === 0 ? (
              <div className="threat-empty light">No source data found.</div>
            ) : (
              sourceRows.map((source, index) => (
                <div className={`source-chip source-${index % 8}`} key={source.name}>
                  <strong>{formatNumber(source.count)}</strong>
                  <span>{source.name}</span>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="threat-feed-status">
          <div className="feed-status-header">
            <h3>FEED STATUS</h3>
            <button onClick={loadThreatIntel}>Run Collection</button>
          </div>

          <div className="feed-table">
            <div className="feed-table-head">
              <span>Feed</span>
              <span>Tier</span>
              <span>Status</span>
              <span>IOCs</span>
              <span>Last Fetch</span>
              <span>Interval</span>
              <span>Error</span>
            </div>

            {feeds.length === 0 ? (
              <div className="feed-empty">No feed status found.</div>
            ) : (
              feeds.map((feed) => (
                <div className="feed-table-row" key={feed.id}>
                  <strong>{feed.name}</strong>
                  <span className="tier-chip">{feed.tier}</span>
                  <span className={`feed-status ${String(feed.status).toLowerCase()}`}>
                    ● {feed.status}
                  </span>
                  <span>{formatNumber(feed.iocs)}</span>
                  <span>{formatTime(feed.lastFetch)}</span>
                  <span>{feed.interval}</span>
                  <span>{feed.error || "—"}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </SiemLayout>
  );
}