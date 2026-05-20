const BASE_SEVERITY = {
  0: 0, 1: 7, 2: 13, 3: 20, 4: 27,
  5: 33, 6: 40, 7: 47, 8: 53,
  9: 60, 10: 67, 11: 73, 12: 80,
  13: 87, 14: 93, 15: 100,
};

const ASSET_MULTIPLIER = {
  domain_controller: 2.0,
  database_server: 1.8,
  financial_erp: 1.9,
  siem_security_tool: 1.7,
  external_app_server: 1.6,
  sensitive_file_server: 1.5,
  internal_app_server: 1.2,
  general_file_server: 1.0,
  admin_workstation: 1.3,
  standard_workstation: 0.7,
  printer_iot: 0.5,
  test_dev: 0.3,
  unknown: 1.0,
};

const USER_MULTIPLIER = {
  domain_admin: 2.0,
  privileged_service_account: 1.9,
  local_admin: 1.7,
  standard_service_account: 1.5,
  power_user: 1.4,
  database_admin: 1.8,
  application_admin: 1.6,
  standard_user: 1.0,
  contractor: 0.8,
  guest: 0.6,
  readonly_service_account: 0.5,
  unknown: 1.0,
};

const MITRE_BOOST = {
  TA0043: 0.05,
  TA0042: 0.1,
  TA0001: 0.2,
  TA0002: 0.3,
  TA0003: 0.35,
  TA0004: 0.4,
  TA0005: 0.45,
  TA0006: 0.5,
  TA0007: 0.15,
  TA0008: 0.5,
  TA0009: 0.45,
  TA0011: 0.55,
  TA0010: 0.6,
  TA0040: 0.7,
};

const TI_BOOST = {
  none: 0,
  suspicious: 0.1,
  malicious: 0.3,
  tor_exit_node: 0.15,
  known_scanner: 0.05,
  geo_anomaly: 0.25,
  blacklisted_low: 0.2,
  blacklisted_high: 0.4,
  apt_ioc: 0.6,
  custom_watchlist: 0.35,
  c2_infrastructure: 0.55,
  recent_compromise: 0.5,
};

const FP_DISCOUNT = {
  confirmed_fp: 0,
  noisy_rule: 0.1,
  high_fp: 0.3,
  moderate_fp: 0.5,
  low_fp: 0.8,
  very_low_fp: 0.95,
  no_history: 1.0,
  unknown: 0.85,
};

const RULE_ANOMALY_BOOST = {
  60122: 0.05,
  60106: 0.15,
  60204: 0.15,
  60108: 0.2,
  60212: 0.2,
  60113: 0.25,
  60230: 0.3,
  5706: 0.15,
  5716: 0.25,
  5710: 0.3,
};

function getLevelAnomalyBoost(level) {
  if (level <= 3) return 0;
  if (level <= 6) return 0.05;
  if (level <= 9) return 0.1;
  if (level <= 12) return 0.2;
  return 0.3;
}

function getTimeMultiplier(dateValue = new Date()) {
  const date = new Date(dateValue);
  const day = date.getDay();
  const hour = date.getHours();

  if (day === 0 || day === 6) return 1.8;
  if (hour >= 0 && hour <= 5) return 1.7;
  if (hour >= 22 && hour <= 23) return 1.5;
  if (hour >= 18 && hour <= 21) return 1.3;
  if (hour >= 6 && hour <= 7) return 1.1;
  return 0.8;
}

function getAssetTypeFromAgent(agent = {}) {
  const name = `${agent.name || ""}`.toLowerCase();

  if (name.includes("dc") || name.includes("ad")) return "domain_controller";
  if (name.includes("db") || name.includes("sql")) return "database_server";
  if (name.includes("siem") || name.includes("wazuh")) return "siem_security_tool";
  if (name.includes("dev") || name.includes("test")) return "test_dev";

  return "standard_workstation";
}

function getSeverityFromRisk(score) {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 35) return "Medium";
  return "Low";
}

function getPriorityFromRisk(score) {
  if (score >= 80) return "P1";
  if (score >= 60) return "P2";
  if (score >= 35) return "P3";
  return "P4";
}

function getTierFromRisk(score) {
  if (score >= 80) return "Tier 3";
  if (score >= 60) return "Tier 2";
  return "Tier 1";
}

function calculateRiskScore({
  wazuhLevel = 3,
  assetType = "unknown",
  userType = "unknown",
  timestamp = new Date(),
  mitreTactics = [],
  tiMatches = [],
  fpType = "unknown",
  ruleId = null,
}) {
  const baseSeverity = BASE_SEVERITY[wazuhLevel] ?? 20;

  const assetMultiplier = ASSET_MULTIPLIER[assetType] ?? 1.0;
  const userMultiplier = USER_MULTIPLIER[userType] ?? 1.0;
  const timeMultiplier = getTimeMultiplier(timestamp);

  const mitreBoost = Math.max(
    0,
    ...mitreTactics.map((tactic) => MITRE_BOOST[tactic] || 0)
  );

  const tiBoost = Math.max(
    0,
    ...tiMatches.map((match) => TI_BOOST[match] || 0)
  );

  const fpDiscount = FP_DISCOUNT[fpType] ?? 0.85;

  const levelAnomalyBoost = getLevelAnomalyBoost(wazuhLevel);
  const ruleAnomalyBoost = RULE_ANOMALY_BOOST[ruleId] || 0;
  const anomalyBoost = Math.max(levelAnomalyBoost, ruleAnomalyBoost);

  const rawScore =
    baseSeverity *
    assetMultiplier *
    userMultiplier *
    timeMultiplier *
    (1 + mitreBoost) *
    (1 + tiBoost) *
    fpDiscount *
    (1 + anomalyBoost);

  const finalScore = Math.max(0, Math.min(100, Math.round(rawScore)));

  return {
    riskScore: finalScore,
    riskBreakdown: {
      baseSeverity,
      assetMultiplier,
      userMultiplier,
      timeMultiplier,
      mitreBoost,
      tiBoost,
      fpDiscount,
      anomalyBoost,
      rawScore: Number(rawScore.toFixed(2)),
    },
  };
}

module.exports = {
  calculateRiskScore,
  getAssetTypeFromAgent,
  getSeverityFromRisk,
  getPriorityFromRisk,
  getTierFromRisk,
};