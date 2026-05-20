const express = require("express");
const Incident = require("../models/Incident");

const router = express.Router();

const VALID_TIERS = [
  "security",
  "investigation",
  "detection_tuning",
  "operational",
  "ai_quality",
];

const VALID_STATUS = [
  "Open",
  "Under Investigation",
  "Investigating",
  "Resolved",
  "Closed",
];

function normalizeIncidentResponse(incident = {}) {
  return {
    ...incident,

    correlationId: incident.correlationId || "",

    parentIncidentId: incident.parentIncidentId || "",

    relatedIncidents: Array.isArray(incident.relatedIncidents)
      ? incident.relatedIncidents
      : [],

    relatedAlerts: Array.isArray(incident.relatedAlerts)
      ? incident.relatedAlerts
      : [],

    enrichment:
      incident.enrichment && typeof incident.enrichment === "object"
        ? incident.enrichment
        : {
            campaign: {},
          },

    campaign:
      incident.enrichment && incident.enrichment.campaign
        ? incident.enrichment.campaign
        : {},

    tags: Array.isArray(incident.tags) ? incident.tags : [],

    riskFactors: Array.isArray(incident.riskFactors)
      ? incident.riskFactors
      : [],

    evidence: Array.isArray(incident.evidence) ? incident.evidence : [],

    playbooks: Array.isArray(incident.playbooks) ? incident.playbooks : [],

    timeline: Array.isArray(incident.timeline) ? incident.timeline : [],

    notes: Array.isArray(incident.notes) ? incident.notes : [],

    analystNotes: Array.isArray(incident.analystNotes)
      ? incident.analystNotes
      : [],

    attackChain: Array.isArray(incident.attackChain)
      ? incident.attackChain
      : [],

    mitreTechniques: Array.isArray(incident.mitreTechniques)
      ? incident.mitreTechniques
      : [],

    indicators: Array.isArray(incident.indicators)
      ? incident.indicators
      : [],

    iocs: Array.isArray(incident.iocs) ? incident.iocs : [],

    hashes: Array.isArray(incident.hashes) ? incident.hashes : [],

    urls: Array.isArray(incident.urls) ? incident.urls : [],

    domains: Array.isArray(incident.domains) ? incident.domains : [],

    processes: Array.isArray(incident.processes)
      ? incident.processes
      : [],

    users: Array.isArray(incident.users) ? incident.users : [],

    networkConnections: Array.isArray(incident.networkConnections)
      ? incident.networkConnections
      : [],

    sourceIPs: Array.isArray(incident.sourceIPs)
      ? incident.sourceIPs
      : [],

    destinationIPs: Array.isArray(incident.destinationIPs)
      ? incident.destinationIPs
      : [],

    soarActions: Array.isArray(incident.soarActions)
      ? incident.soarActions
      : [],

    executedActions: Array.isArray(incident.executedActions)
      ? incident.executedActions
      : [],

    tickets: Array.isArray(incident.tickets) ? incident.tickets : [],
  };
}

function buildBaseQuery(req) {
  const query = {
    tier: { $in: VALID_TIERS },
    incidentKey: { $exists: true, $ne: null },
  };

  if (req.query.tier && VALID_TIERS.includes(req.query.tier)) {
    query.tier = req.query.tier;
  }

  if (req.query.status) {
    const status = req.query.status;

    if (status === "open") {
      query.status = { $in: ["Open"] };
    } else if (status === "investigating") {
      query.status = { $in: ["Under Investigation", "Investigating"] };
    } else if (status === "resolved") {
      query.status = { $in: ["Resolved", "Closed"] };
    } else {
      query.status = status;
    }
  }

  if (req.query.severity) {
    query.severity = req.query.severity;
  }

  if (req.query.priority) {
    query.priority = req.query.priority;
  }

  if (req.query.verdict) {
    query.verdict = req.query.verdict;
  }

  if (req.query.host) {
    query.host = { $regex: req.query.host.trim(), $options: "i" };
  }

  if (req.query.user) {
    query.users = { $regex: req.query.user.trim(), $options: "i" };
  }

  if (req.query.process) {
    query.processes = { $regex: req.query.process.trim(), $options: "i" };
  }

  if (req.query.indicator) {
    query.indicators = { $regex: req.query.indicator.trim(), $options: "i" };
  }

  if (req.query.tenant_id) {
    query.tenant_id = req.query.tenant_id;
  }

  if (req.query.requiresHumanReview === "true") {
    query.requiresHumanReview = true;
  }

  if (req.query.suppressionCandidate === "true") {
    query.suppressionCandidate = true;
  }

  if (req.query.escalationStatus) {
    query.escalationStatus = req.query.escalationStatus;
  }

  if (req.query.search) {
    const search = req.query.search.trim();

    query.$or = [
      { incidentKey: { $regex: search, $options: "i" } },
      { title: { $regex: search, $options: "i" } },
      { host: { $regex: search, $options: "i" } },
      { ip: { $regex: search, $options: "i" } },
      { classification: { $regex: search, $options: "i" } },
      { verdict: { $regex: search, $options: "i" } },
      { indicators: { $regex: search, $options: "i" } },
      { users: { $regex: search, $options: "i" } },
      { processes: { $regex: search, $options: "i" } },
      { mitreTechniques: { $regex: search, $options: "i" } },
      { attackChain: { $regex: search, $options: "i" } },
      { tags: { $regex: search, $options: "i" } },
      { riskFactors: { $regex: search, $options: "i" } },
      { correlationId: { $regex: search, $options: "i" } },
    ];
  }

  return query;
}

function buildTimelineEvent(type, actor, message, extra = {}) {
  return {
    time: new Date().toISOString(),
    type,
    actor: actor || "system",
    message,
    ...extra,
  };
}

function normalizeStatus(status) {
  if (!status) return "Open";

  const value = String(status).toLowerCase();

  if (value === "open") return "Open";
  if (value === "under investigation") return "Under Investigation";
  if (value === "investigating") return "Under Investigation";
  if (value === "resolved") return "Resolved";
  if (value === "closed") return "Closed";

  return status;
}

function getCloseFields(status, analyst, resolution = "") {
  const normalized = normalizeStatus(status);

  if (normalized === "Closed" || normalized === "Resolved") {
    return {
      closedAt: new Date(),
      closedBy: analyst || "system",
      resolution,
    };
  }

  return {
    closedAt: null,
    closedBy: "",
    resolution: "",
  };
}

router.get("/", async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
    const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
    const skip = (page - 1) * limit;
    const query = buildBaseQuery(req);

    const sortField = req.query.sortBy || "lastSeen";
    const sortOrder = req.query.sortOrder === "asc" ? 1 : -1;

    const [rawIncidents, total] = await Promise.all([
      Incident.find(query)
        .sort({ [sortField]: sortOrder, updatedAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      Incident.countDocuments(query),
    ]);

    const incidents = rawIncidents.map(normalizeIncidentResponse);

    return res.json({
      data: incidents,
      incidents,
      total,
      page,
      limit,
      hasMore: skip + incidents.length < total,
    });
  } catch (err) {
    console.error("Fetch incidents error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

router.get("/summary/counts", async (req, res) => {
  try {
    const baseQuery = buildBaseQuery(req);

    const [
      byTier,
      byStatus,
      bySeverity,
      byPriority,
      byVerdict,
      byEscalation,
      total,
      open,
      critical,
      high,
      humanReview,
      suppressionCandidates,
      campaignIncidents,
    ] = await Promise.all([
      Incident.aggregate([
        { $match: baseQuery },
        { $group: { _id: "$tier", count: { $sum: 1 } } },
      ]),
      Incident.aggregate([
        { $match: baseQuery },
        { $group: { _id: "$status", count: { $sum: 1 } } },
      ]),
      Incident.aggregate([
        { $match: baseQuery },
        { $group: { _id: "$severity", count: { $sum: 1 } } },
      ]),
      Incident.aggregate([
        { $match: baseQuery },
        { $group: { _id: "$priority", count: { $sum: 1 } } },
      ]),
      Incident.aggregate([
        { $match: baseQuery },
        { $group: { _id: "$verdict", count: { $sum: 1 } } },
      ]),
      Incident.aggregate([
        { $match: baseQuery },
        { $group: { _id: "$escalationStatus", count: { $sum: 1 } } },
      ]),
      Incident.countDocuments(baseQuery),
      Incident.countDocuments({
        ...baseQuery,
        status: { $nin: ["Closed", "Resolved"] },
      }),
      Incident.countDocuments({
        ...baseQuery,
        severity: "Critical",
      }),
      Incident.countDocuments({
        ...baseQuery,
        severity: "High",
      }),
      Incident.countDocuments({
        ...baseQuery,
        requiresHumanReview: true,
      }),
      Incident.countDocuments({
        ...baseQuery,
        suppressionCandidate: true,
      }),
      Incident.countDocuments({
        ...baseQuery,
        correlationId: { $exists: true, $ne: "" },
      }),
    ]);

    return res.json({
      total,
      open,
      critical,
      high,
      humanReview,
      suppressionCandidates,
      campaignIncidents,
      byTier,
      byStatus,
      bySeverity,
      byPriority,
      byVerdict,
      byEscalation,
    });
  } catch (err) {
    console.error("Incident summary error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

router.get("/attack-chain", async (req, res) => {
  try {
    const query = buildBaseQuery(req);

    const data = await Incident.aggregate([
      { $match: query },
      { $unwind: "$attackChain" },
      {
        $group: {
          _id: "$attackChain",
          count: { $sum: 1 },
          maxRisk: { $max: "$riskScore" },
          latestSeen: { $max: "$lastSeen" },
        },
      },
      { $sort: { maxRisk: -1, count: -1 } },
    ]);

    return res.json({
      data,
      total: data.length,
    });
  } catch (err) {
    console.error("Attack-chain summary error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

router.get("/campaigns", async (req, res) => {
  try {
    const query = {
      ...buildBaseQuery(req),
      $or: [
        { correlationId: { $exists: true, $ne: "" } },
        { "enrichment.campaign.campaignDetected": true },
        { escalationStatus: "campaign_escalation" },
      ],
    };

    const rawIncidents = await Incident.find(query)
      .sort({ lastSeen: -1, updatedAt: -1 })
      .limit(Math.min(parseInt(req.query.limit, 10) || 100, 500))
      .lean();

    const incidents = rawIncidents.map(normalizeIncidentResponse);

    return res.json({
      data: incidents,
      total: incidents.length,
    });
  } catch (err) {
    console.error("Campaign incidents error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

router.get("/threat-intel", async (req, res) => {
  try {
    const query = buildBaseQuery(req);

    const rawIncidents = await Incident.find(query)
      .sort({ updatedAt: -1 })
      .limit(300)
      .select(
        "incidentKey title severity riskScore host indicators threatIntel threatFeedHits maliciousIPs maliciousHashes suspiciousDomains lastSeen enrichment correlationId tags riskFactors relatedIncidents"
      )
      .lean();

    const incidents = rawIncidents.map(normalizeIncidentResponse);

    const maliciousIPs = new Set();
    const maliciousHashes = new Set();
    const suspiciousDomains = new Set();
    const indicators = new Set();

    incidents.forEach((incident) => {
      (incident.maliciousIPs || []).forEach((item) => maliciousIPs.add(item));
      (incident.maliciousHashes || []).forEach((item) =>
        maliciousHashes.add(item)
      );
      (incident.suspiciousDomains || []).forEach((item) =>
        suspiciousDomains.add(item)
      );
      (incident.indicators || []).forEach((item) => indicators.add(item));
    });

    return res.json({
      data: incidents,
      summary: {
        incidents: incidents.length,
        indicators: indicators.size,
        maliciousIPs: maliciousIPs.size,
        maliciousHashes: maliciousHashes.size,
        suspiciousDomains: suspiciousDomains.size,
      },
    });
  } catch (err) {
    console.error("Threat-intel incidents error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

router.get("/:incidentKey", async (req, res) => {
  try {
    const incident = await Incident.findOne({
      incidentKey: req.params.incidentKey,
      tier: { $in: VALID_TIERS },
    }).lean();

    if (!incident) {
      return res.status(404).json({ message: "Incident not found" });
    }

    return res.json(normalizeIncidentResponse(incident));
  } catch (err) {
    console.error("Fetch incident error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

router.post("/update", async (req, res) => {
  try {
    const data = req.body;

    if (!data.incidentKey) {
      return res.status(400).json({ message: "incidentKey required" });
    }

    const updateData = { ...data };

    delete updateData._id;
    delete updateData.createdAt;
    delete updateData.updatedAt;
    delete updateData.timeline;
    delete updateData.notes;
    delete updateData.analystNotes;

    if (updateData.tier && !VALID_TIERS.includes(updateData.tier)) {
      return res.status(400).json({ message: "Invalid incident tier" });
    }

    if (updateData.status) {
      updateData.status = normalizeStatus(updateData.status);
      Object.assign(
        updateData,
        getCloseFields(updateData.status, data.analyst || data.updatedBy)
      );
    }

    const timelineEvent = buildTimelineEvent(
      "INCIDENT_UPDATED",
      data.analyst || data.updatedBy || "system",
      "Incident updated"
    );

    const updated = await Incident.findOneAndUpdate(
      { incidentKey: data.incidentKey },
      {
        $set: updateData,
        $push: {
          timeline: timelineEvent,
        },
      },
      {
        new: true,
        upsert: false,
      }
    ).lean();

    if (!updated) {
      return res.status(404).json({ message: "Incident not found" });
    }

    return res.json(normalizeIncidentResponse(updated));
  } catch (err) {
    console.error("Update error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

router.patch("/:incidentKey/status", async (req, res) => {
  try {
    const { status, analyst, note, resolution } = req.body;

    if (!status) {
      return res.status(400).json({ message: "status required" });
    }

    const normalizedStatus = normalizeStatus(status);

    if (!VALID_STATUS.includes(normalizedStatus)) {
      return res.status(400).json({ message: "Invalid status" });
    }

    const timelineEvent = buildTimelineEvent(
      "STATUS_UPDATED",
      analyst || "system",
      `Incident status changed to ${normalizedStatus}`
    );

    const update = {
      $set: {
        status: normalizedStatus,
        ...getCloseFields(normalizedStatus, analyst, resolution || ""),
      },
      $push: {
        timeline: timelineEvent,
      },
    };

    if (note) {
      const noteEntry = {
        time: new Date().toISOString(),
        analyst: analyst || "system",
        note,
      };

      update.$push.notes = noteEntry;
      update.$push.analystNotes = noteEntry;
    }

    const updated = await Incident.findOneAndUpdate(
      {
        incidentKey: req.params.incidentKey,
        tier: { $in: VALID_TIERS },
      },
      update,
      { new: true }
    ).lean();

    if (!updated) {
      return res.status(404).json({ message: "Incident not found" });
    }

    return res.json(normalizeIncidentResponse(updated));
  } catch (err) {
    console.error("Status update error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

router.post("/:incidentKey/notes", async (req, res) => {
  try {
    const { analyst, note } = req.body;

    if (!note) {
      return res.status(400).json({ message: "note required" });
    }

    const noteEntry = {
      time: new Date().toISOString(),
      analyst: analyst || "system",
      note,
    };

    const timelineEvent = buildTimelineEvent(
      "NOTE_ADDED",
      analyst || "system",
      "Analyst note added"
    );

    const updated = await Incident.findOneAndUpdate(
      {
        incidentKey: req.params.incidentKey,
        tier: { $in: VALID_TIERS },
      },
      {
        $push: {
          notes: noteEntry,
          analystNotes: noteEntry,
          timeline: timelineEvent,
        },
      },
      { new: true }
    ).lean();

    if (!updated) {
      return res.status(404).json({ message: "Incident not found" });
    }

    return res.json(normalizeIncidentResponse(updated));
  } catch (err) {
    console.error("Add note error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

router.post("/:incidentKey/soar-action", async (req, res) => {
  try {
    const {
      action,
      target,
      analyst,
      approval_required = true,
      status = "queued",
    } = req.body;

    if (!action) {
      return res.status(400).json({ message: "action required" });
    }

    const actionEntry = {
      action,
      target: target || "",
      status,
      approval_required,
      requested_by: analyst || "system",
      requested_at: new Date().toISOString(),
      executed_at: null,
      result: "",
    };

    const timelineEvent = buildTimelineEvent(
      "SOAR_ACTION_QUEUED",
      analyst || "system",
      `SOAR action queued: ${action}`,
      {
        action,
        target: target || "",
      }
    );

    const updated = await Incident.findOneAndUpdate(
      {
        incidentKey: req.params.incidentKey,
        tier: { $in: VALID_TIERS },
      },
      {
        $push: {
          soarActions: actionEntry,
          timeline: timelineEvent,
        },
      },
      { new: true }
    ).lean();

    if (!updated) {
      return res.status(404).json({ message: "Incident not found" });
    }

    return res.json(normalizeIncidentResponse(updated));
  } catch (err) {
    console.error("SOAR action error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

router.post("/:incidentKey/enrich-investigation", async (req, res) => {
  try {
    const { enrichInvestigationIncident } = require("../services/investigationEngine");

    const incident = await enrichInvestigationIncident(
      req.params.incidentKey,
      req.body.actor || "system"
    );

    if (!incident) {
      return res.status(404).json({
        message: "Incident not found",
      });
    }

    return res.json(incident);
  } catch (err) {
    console.error("Enrich investigation error:", err.message);

    return res.status(500).json({
      error: err.message,
    });
  }
});

module.exports = router;