/**
 * Milestone 18: Probabilistic Breach Forecasting — Types
 */

export interface BreachForecast {
  organisationId: string;
  calculatedAt: string;
  windows: {
    days30: ProbabilityWindow;
    days60: ProbabilityWindow;
    days90: ProbabilityWindow;
  };
  riskNarrative: string;
  confidenceLevel: number;
  simulationRuns: number;
}

export interface ProbabilityWindow {
  probability: number;
  confidenceInterval: { lower: number; upper: number };
}

export interface RiskFactor {
  id: string;
  name: string;
  category: 'vulnerability' | 'exposure' | 'threat_landscape' | 'remediation_velocity';
  weight: number;
  currentValue: number;
  impact: 'increases_risk' | 'decreases_risk';
  description: string;
}

export interface WhatIfScenario {
  organisationId: string;
  scenarioDescription: string;
  remediations: string[];
  originalForecast: BreachForecast;
  adjustedForecast: BreachForecast;
  riskReduction: {
    days30: number;
    days60: number;
    days90: number;
  };
}

export interface ForecastHistoryEntry {
  organisationId: string;
  calculatedAt: string;
  probability30: number;
  probability60: number;
  probability90: number;
}

export interface VulnerabilityInventory {
  critical: number;
  high: number;
  medium: number;
  low: number;
  averageExposureDays: number;
  remediationVelocity: number; // vulns fixed per week
  totalAssets: number;
  exposedAssets: number;
}

export interface IndustryThreatData {
  industry: string;
  annualBreachRate: number; // probability per year
  averageAttacksPerMonth: number;
  topAttackVectors: string[];
}
