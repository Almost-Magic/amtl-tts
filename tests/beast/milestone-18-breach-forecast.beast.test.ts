/**
 * Beast Tests — Milestone 18: Probabilistic Breach Forecasting
 *
 * Tests Monte Carlo simulation, probability calculations, what-if scenarios,
 * risk factors, trend history, and executive narratives.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import * as service from '../../src/services/breach-forecast.js';
import type { VulnerabilityInventory } from '../../src/models/breach-forecast.js';

beforeEach(() => {
  service._resetState();
});

const HIGH_RISK_INVENTORY: VulnerabilityInventory = {
  critical: 5,
  high: 12,
  medium: 30,
  low: 50,
  averageExposureDays: 45,
  remediationVelocity: 3,
  totalAssets: 200,
  exposedAssets: 80,
};

const LOW_RISK_INVENTORY: VulnerabilityInventory = {
  critical: 0,
  high: 1,
  medium: 5,
  low: 10,
  averageExposureDays: 7,
  remediationVelocity: 15,
  totalAssets: 200,
  exposedAssets: 10,
};

describe('Milestone 18: Probabilistic Breach Forecasting', () => {
  // ─── Probability Calculation ─────────────────────────────────

  it('Beast 18.1 — should calculate breach probability for all three windows', () => {
    const forecast = service.calculateForecast('org-001', HIGH_RISK_INVENTORY, 'finance', 5000, 42);

    expect(forecast.organisationId).toBe('org-001');
    expect(forecast.windows.days30.probability).toBeGreaterThan(0);
    expect(forecast.windows.days60.probability).toBeGreaterThan(0);
    expect(forecast.windows.days90.probability).toBeGreaterThan(0);
  });

  it('Beast 18.2 — 90-day probability should be >= 60-day >= 30-day', () => {
    const forecast = service.calculateForecast('org-001', HIGH_RISK_INVENTORY, 'finance', 10000, 42);

    expect(forecast.windows.days90.probability).toBeGreaterThanOrEqual(forecast.windows.days60.probability);
    expect(forecast.windows.days60.probability).toBeGreaterThanOrEqual(forecast.windows.days30.probability);
  });

  it('Beast 18.3 — high-risk inventory should produce higher probabilities than low-risk', () => {
    const highRisk = service.calculateForecast('org-high', HIGH_RISK_INVENTORY, 'finance', 10000, 42);
    const lowRisk = service.calculateForecast('org-low', LOW_RISK_INVENTORY, 'finance', 10000, 42);

    expect(highRisk.windows.days30.probability).toBeGreaterThan(lowRisk.windows.days30.probability);
    expect(highRisk.windows.days90.probability).toBeGreaterThan(lowRisk.windows.days90.probability);
  });

  it('Beast 18.4 — probabilities should be between 0 and 1', () => {
    const forecast = service.calculateForecast('org-001', HIGH_RISK_INVENTORY, 'finance', 5000, 42);

    for (const window of [forecast.windows.days30, forecast.windows.days60, forecast.windows.days90]) {
      expect(window.probability).toBeGreaterThanOrEqual(0);
      expect(window.probability).toBeLessThanOrEqual(1);
      expect(window.confidenceInterval.lower).toBeGreaterThanOrEqual(0);
      expect(window.confidenceInterval.upper).toBeLessThanOrEqual(1);
    }
  });

  // ─── Confidence Intervals ────────────────────────────────────

  it('Beast 18.5 — should produce 95% confidence intervals', () => {
    const forecast = service.calculateForecast('org-001', HIGH_RISK_INVENTORY, 'technology', 10000, 42);

    expect(forecast.confidenceLevel).toBe(0.95);

    for (const window of [forecast.windows.days30, forecast.windows.days60, forecast.windows.days90]) {
      expect(window.confidenceInterval.lower).toBeLessThanOrEqual(window.probability);
      expect(window.confidenceInterval.upper).toBeGreaterThanOrEqual(window.probability);
    }
  });

  // ─── Deterministic Simulation ────────────────────────────────

  it('Beast 18.6 — same seed should produce identical results', () => {
    const run1 = service.calculateForecast('org-001', HIGH_RISK_INVENTORY, 'finance', 5000, 123);
    const run2 = service.calculateForecast('org-001', HIGH_RISK_INVENTORY, 'finance', 5000, 123);

    expect(run1.windows.days30.probability).toBe(run2.windows.days30.probability);
    expect(run1.windows.days60.probability).toBe(run2.windows.days60.probability);
    expect(run1.windows.days90.probability).toBe(run2.windows.days90.probability);
  });

  // ─── What-If Scenarios ───────────────────────────────────────

  it('Beast 18.7 — what-if: fixing critical vulns should reduce risk', () => {
    const scenario = service.whatIfScenario(
      'org-001',
      HIGH_RISK_INVENTORY,
      ['fix_critical'],
      'finance',
      10000,
      42,
    );

    expect(scenario.riskReduction.days30).toBeGreaterThan(0);
    expect(scenario.riskReduction.days90).toBeGreaterThan(0);
    expect(scenario.adjustedForecast.windows.days30.probability)
      .toBeLessThan(scenario.originalForecast.windows.days30.probability);
  });

  it('Beast 18.8 — what-if: patching all vulns should significantly reduce risk', () => {
    const scenario = service.whatIfScenario(
      'org-001',
      HIGH_RISK_INVENTORY,
      ['patch_all'],
      'finance',
      10000,
      42,
    );

    expect(scenario.riskReduction.days90).toBeGreaterThan(0);
    expect(scenario.adjustedForecast.windows.days90.probability)
      .toBeLessThan(scenario.originalForecast.windows.days90.probability);
  });

  it('Beast 18.9 — what-if: multiple remediations should have combined effect', () => {
    const singleFix = service.whatIfScenario(
      'org-001', HIGH_RISK_INVENTORY, ['fix_critical'], 'finance', 10000, 42,
    );
    const multiFix = service.whatIfScenario(
      'org-001', HIGH_RISK_INVENTORY, ['fix_critical', 'fix_high', 'reduce_exposure'], 'finance', 10000, 42,
    );

    expect(multiFix.riskReduction.days90).toBeGreaterThanOrEqual(singleFix.riskReduction.days90);
  });

  // ─── History Tracking ────────────────────────────────────────

  it('Beast 18.10 — should track forecast history over time', () => {
    service.calculateForecast('org-trend', HIGH_RISK_INVENTORY, 'finance', 1000, 1);
    service.calculateForecast('org-trend', LOW_RISK_INVENTORY, 'finance', 1000, 2);

    const history = service.getForecastHistory('org-trend');
    expect(history).toHaveLength(2);
    expect(history[0].probability30).toBeGreaterThan(history[1].probability30);
  });

  // ─── Risk Factors ────────────────────────────────────────────

  it('Beast 18.11 — should generate contributing risk factors', () => {
    service.calculateForecast('org-factors', HIGH_RISK_INVENTORY, 'finance', 1000, 42);

    const factors = service.getRiskFactors('org-factors');
    expect(factors.length).toBeGreaterThanOrEqual(4);

    const categories = factors.map((f) => f.category);
    expect(categories).toContain('vulnerability');
    expect(categories).toContain('exposure');
    expect(categories).toContain('remediation_velocity');
    expect(categories).toContain('threat_landscape');
  });

  // ─── Executive Narrative ─────────────────────────────────────

  it('Beast 18.12 — should generate executive-friendly risk narrative', () => {
    const forecast = service.calculateForecast('org-001', HIGH_RISK_INVENTORY, 'finance', 5000, 42);

    expect(forecast.riskNarrative).toBeDefined();
    expect(forecast.riskNarrative.length).toBeGreaterThan(50);
    expect(forecast.riskNarrative).toContain('Monte Carlo');
    expect(forecast.riskNarrative).toContain('%');
  });

  // ─── Industry Differentiation ────────────────────────────────

  it('Beast 18.13 — different industries should produce different forecasts', () => {
    const finance = service.calculateForecast('org-fin', HIGH_RISK_INVENTORY, 'finance', 10000, 42);
    const tech = service.calculateForecast('org-tech', HIGH_RISK_INVENTORY, 'technology', 10000, 42);

    // They should differ due to different industry threat rates
    const finProb = finance.windows.days30.probability;
    const techProb = tech.windows.days30.probability;
    expect(finProb).not.toBe(techProb);
  });

  it('Beast 18.14 — should handle unknown industry gracefully with defaults', () => {
    const forecast = service.calculateForecast('org-001', HIGH_RISK_INVENTORY, 'widgets', 5000, 42);

    expect(forecast.organisationId).toBe('org-001');
    expect(forecast.windows.days30.probability).toBeGreaterThan(0);
  });
});
