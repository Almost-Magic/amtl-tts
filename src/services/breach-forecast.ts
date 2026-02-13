/**
 * Milestone 18: Probabilistic Breach Forecasting — Service
 *
 * Uses Monte Carlo simulation to estimate breach probability
 * within 30/60/90 day windows based on vulnerability inventory,
 * exposure surface, industry threat data, and remediation velocity.
 */
import { generateId } from '../utils/id.js';
import { clock } from '../utils/clock.js';
import type {
  BreachForecast,
  ProbabilityWindow,
  RiskFactor,
  WhatIfScenario,
  ForecastHistoryEntry,
  VulnerabilityInventory,
  IndustryThreatData,
} from '../models/breach-forecast.js';

// In-memory stores
const forecastHistory: Map<string, ForecastHistoryEntry[]> = new Map();
const riskFactors: Map<string, RiskFactor[]> = new Map();

// Industry baseline threat data
const INDUSTRY_THREAT_DATA: Record<string, IndustryThreatData> = {
  finance: { industry: 'finance', annualBreachRate: 0.27, averageAttacksPerMonth: 85, topAttackVectors: ['phishing', 'credential_stuffing', 'ransomware'] },
  healthcare: { industry: 'healthcare', annualBreachRate: 0.34, averageAttacksPerMonth: 72, topAttackVectors: ['ransomware', 'insider_threat', 'phishing'] },
  technology: { industry: 'technology', annualBreachRate: 0.22, averageAttacksPerMonth: 120, topAttackVectors: ['supply_chain', 'zero_day', 'credential_stuffing'] },
  government: { industry: 'government', annualBreachRate: 0.19, averageAttacksPerMonth: 95, topAttackVectors: ['apt', 'phishing', 'insider_threat'] },
  retail: { industry: 'retail', annualBreachRate: 0.30, averageAttacksPerMonth: 60, topAttackVectors: ['web_application', 'pos_malware', 'phishing'] },
  default: { industry: 'default', annualBreachRate: 0.25, averageAttacksPerMonth: 50, topAttackVectors: ['phishing', 'ransomware', 'credential_stuffing'] },
};

/** Seeded pseudo-random number generator for reproducible simulations */
function seededRandom(seed: number): () => number {
  let s = seed;
  return () => {
    s = (s * 1664525 + 1013904223) & 0xffffffff;
    return (s >>> 0) / 0xffffffff;
  };
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

/** Calculate base daily breach probability from vulnerability inventory and threat data */
function calculateBaseDailyProbability(
  inventory: VulnerabilityInventory,
  threatData: IndustryThreatData,
): number {
  // Convert annual rate to daily
  const dailyBaseRate = 1 - Math.pow(1 - threatData.annualBreachRate, 1 / 365);

  // Severity weighting
  const severityScore =
    inventory.critical * 10 +
    inventory.high * 5 +
    inventory.medium * 2 +
    inventory.low * 0.5;

  // Exposure multiplier (more exposed assets = higher risk)
  const exposureRatio = inventory.totalAssets > 0
    ? inventory.exposedAssets / inventory.totalAssets
    : 0;

  // Remediation velocity discount (faster fixes = lower risk)
  const totalVulns = inventory.critical + inventory.high + inventory.medium + inventory.low;
  const remediationRatio = totalVulns > 0
    ? clamp(inventory.remediationVelocity / totalVulns, 0, 1)
    : 1;
  const remediationDiscount = 1 - (remediationRatio * 0.3);

  // Exposure duration amplifier
  const durationMultiplier = 1 + (inventory.averageExposureDays / 365) * 0.5;

  // Combined probability
  const severityMultiplier = 1 + (severityScore / 100) * 0.5;
  const exposureMultiplier = 1 + exposureRatio * 0.4;

  const dailyProbability = dailyBaseRate *
    severityMultiplier *
    exposureMultiplier *
    durationMultiplier *
    remediationDiscount;

  return clamp(dailyProbability, 0.0001, 0.1);
}

/** Run Monte Carlo simulation for breach probability over N days */
function monteCarloSimulation(
  dailyProbability: number,
  days: number,
  runs: number,
  seed: number,
): ProbabilityWindow {
  const rng = seededRandom(seed);
  let breachCount = 0;
  const results: number[] = [];

  for (let run = 0; run < runs; run++) {
    let breached = false;
    for (let day = 0; day < days; day++) {
      // Add daily variance (±20%)
      const variance = 0.8 + rng() * 0.4;
      if (rng() < dailyProbability * variance) {
        breached = true;
        break;
      }
    }
    results.push(breached ? 1 : 0);
    if (breached) breachCount++;
  }

  const probability = breachCount / runs;

  // Calculate 95% confidence interval using normal approximation
  const standardError = Math.sqrt((probability * (1 - probability)) / runs);
  const zScore = 1.96;

  return {
    probability: Math.round(probability * 10000) / 10000,
    confidenceInterval: {
      lower: Math.round(clamp(probability - zScore * standardError, 0, 1) * 10000) / 10000,
      upper: Math.round(clamp(probability + zScore * standardError, 0, 1) * 10000) / 10000,
    },
  };
}

/** Generate executive-friendly risk narrative */
function generateNarrative(forecast: BreachForecast, industry: string): string {
  const p30 = forecast.windows.days30.probability;
  const p90 = forecast.windows.days90.probability;

  let urgency: string;
  if (p30 > 0.5) {
    urgency = 'Critical — immediate action required';
  } else if (p30 > 0.3) {
    urgency = 'High — urgent remediation recommended';
  } else if (p30 > 0.15) {
    urgency = 'Elevated — proactive measures advised';
  } else {
    urgency = 'Moderate — continue monitoring';
  }

  return `Risk Assessment for ${industry} organisation: ${urgency}. ` +
    `There is a ${(p30 * 100).toFixed(1)}% probability of breach within 30 days ` +
    `and ${(p90 * 100).toFixed(1)}% within 90 days. ` +
    `Based on ${forecast.simulationRuns.toLocaleString()} Monte Carlo simulations ` +
    `with ${(forecast.confidenceLevel * 100).toFixed(0)}% confidence.`;
}

/** Build risk factors for an organisation */
function buildRiskFactors(inventory: VulnerabilityInventory, industry: string): RiskFactor[] {
  const factors: RiskFactor[] = [];

  if (inventory.critical > 0) {
    factors.push({
      id: generateId(),
      name: 'Critical vulnerabilities',
      category: 'vulnerability',
      weight: 0.35,
      currentValue: inventory.critical,
      impact: 'increases_risk',
      description: `${inventory.critical} critical vulnerabilities present in the environment`,
    });
  }

  if (inventory.high > 0) {
    factors.push({
      id: generateId(),
      name: 'High-severity vulnerabilities',
      category: 'vulnerability',
      weight: 0.2,
      currentValue: inventory.high,
      impact: 'increases_risk',
      description: `${inventory.high} high-severity vulnerabilities requiring attention`,
    });
  }

  factors.push({
    id: generateId(),
    name: 'Exposure surface',
    category: 'exposure',
    weight: 0.2,
    currentValue: inventory.totalAssets > 0 ? inventory.exposedAssets / inventory.totalAssets : 0,
    impact: 'increases_risk',
    description: `${inventory.exposedAssets} of ${inventory.totalAssets} assets are exposed`,
  });

  factors.push({
    id: generateId(),
    name: 'Average exposure duration',
    category: 'exposure',
    weight: 0.1,
    currentValue: inventory.averageExposureDays,
    impact: 'increases_risk',
    description: `Vulnerabilities remain unpatched for an average of ${inventory.averageExposureDays} days`,
  });

  factors.push({
    id: generateId(),
    name: 'Remediation velocity',
    category: 'remediation_velocity',
    weight: 0.15,
    currentValue: inventory.remediationVelocity,
    impact: 'decreases_risk',
    description: `${inventory.remediationVelocity} vulnerabilities remediated per week`,
  });

  const threatData = INDUSTRY_THREAT_DATA[industry] ?? INDUSTRY_THREAT_DATA['default'];
  factors.push({
    id: generateId(),
    name: 'Industry threat landscape',
    category: 'threat_landscape',
    weight: 0.15,
    currentValue: threatData.averageAttacksPerMonth,
    impact: 'increases_risk',
    description: `${industry} sector experiences ~${threatData.averageAttacksPerMonth} attacks per month on average`,
  });

  return factors;
}

export function calculateForecast(
  organisationId: string,
  inventory: VulnerabilityInventory,
  industry: string = 'default',
  simulationRuns: number = 10000,
  seed: number = 42,
): BreachForecast {
  const threatData = INDUSTRY_THREAT_DATA[industry] ?? INDUSTRY_THREAT_DATA['default'];
  const dailyProbability = calculateBaseDailyProbability(inventory, threatData);

  const forecast: BreachForecast = {
    organisationId,
    calculatedAt: clock.isoNow(),
    windows: {
      days30: monteCarloSimulation(dailyProbability, 30, simulationRuns, seed),
      days60: monteCarloSimulation(dailyProbability, 60, simulationRuns, seed + 1),
      days90: monteCarloSimulation(dailyProbability, 90, simulationRuns, seed + 2),
    },
    riskNarrative: '',
    confidenceLevel: 0.95,
    simulationRuns,
  };

  forecast.riskNarrative = generateNarrative(forecast, industry);

  // Store risk factors
  const factors = buildRiskFactors(inventory, industry);
  riskFactors.set(organisationId, factors);

  // Store in history
  const history = forecastHistory.get(organisationId) ?? [];
  history.push({
    organisationId,
    calculatedAt: forecast.calculatedAt,
    probability30: forecast.windows.days30.probability,
    probability60: forecast.windows.days60.probability,
    probability90: forecast.windows.days90.probability,
  });
  forecastHistory.set(organisationId, history);

  return forecast;
}

export function whatIfScenario(
  organisationId: string,
  originalInventory: VulnerabilityInventory,
  remediations: string[],
  industry: string = 'default',
  simulationRuns: number = 10000,
  seed: number = 42,
): WhatIfScenario {
  // Calculate original forecast
  const originalForecast = calculateForecast(
    organisationId, originalInventory, industry, simulationRuns, seed,
  );

  // Apply remediations to create adjusted inventory
  const adjusted = { ...originalInventory };
  for (const remediation of remediations) {
    switch (remediation) {
      case 'fix_critical':
        adjusted.critical = 0;
        break;
      case 'fix_high':
        adjusted.high = 0;
        break;
      case 'fix_medium':
        adjusted.medium = Math.floor(adjusted.medium / 2);
        break;
      case 'reduce_exposure':
        adjusted.exposedAssets = Math.floor(adjusted.exposedAssets / 2);
        break;
      case 'improve_velocity':
        adjusted.remediationVelocity = adjusted.remediationVelocity * 2;
        break;
      case 'patch_all':
        adjusted.critical = 0;
        adjusted.high = 0;
        adjusted.medium = 0;
        adjusted.low = 0;
        break;
    }
  }

  const adjustedForecast = calculateForecast(
    organisationId, adjusted, industry, simulationRuns, seed + 100,
  );

  return {
    organisationId,
    scenarioDescription: `What-if scenario: ${remediations.join(', ')}`,
    remediations,
    originalForecast,
    adjustedForecast,
    riskReduction: {
      days30: Math.round((originalForecast.windows.days30.probability - adjustedForecast.windows.days30.probability) * 10000) / 10000,
      days60: Math.round((originalForecast.windows.days60.probability - adjustedForecast.windows.days60.probability) * 10000) / 10000,
      days90: Math.round((originalForecast.windows.days90.probability - adjustedForecast.windows.days90.probability) * 10000) / 10000,
    },
  };
}

export function getForecastHistory(organisationId: string): ForecastHistoryEntry[] {
  return forecastHistory.get(organisationId) ?? [];
}

export function getRiskFactors(organisationId: string): RiskFactor[] {
  return riskFactors.get(organisationId) ?? [];
}

/** Reset all state — used in tests */
export function _resetState(): void {
  forecastHistory.clear();
  riskFactors.clear();
}
