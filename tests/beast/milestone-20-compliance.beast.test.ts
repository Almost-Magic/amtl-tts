/**
 * Beast Tests — Milestone 20: Compliance Autopilot
 *
 * Tests Essential Eight, ISO 27001, APRA CPS 234, Privacy Act NDB,
 * gap analysis, report generation, and framework listing.
 */
import { describe, it, expect } from 'vitest';
import * as service from '../../src/services/compliance.js';
import type { SecurityPosture } from '../../src/models/compliance.js';

const STRONG_POSTURE: SecurityPosture = {
  patchManagement: 'strong',
  accessControls: 'strong',
  networkSegmentation: true,
  mfaEnabled: true,
  backupsTested: true,
  incidentResponsePlan: true,
  securityTraining: true,
  vulnerabilityScanningFrequency: 'continuous',
  dataClassification: true,
  encryptionAtRest: true,
  encryptionInTransit: true,
  loggingAndMonitoring: 'comprehensive',
  thirdPartyRiskManagement: true,
};

const WEAK_POSTURE: SecurityPosture = {
  patchManagement: 'weak',
  accessControls: 'weak',
  networkSegmentation: false,
  mfaEnabled: false,
  backupsTested: false,
  incidentResponsePlan: false,
  securityTraining: false,
  vulnerabilityScanningFrequency: 'never',
  dataClassification: false,
  encryptionAtRest: false,
  encryptionInTransit: false,
  loggingAndMonitoring: 'none',
  thirdPartyRiskManagement: false,
};

const MODERATE_POSTURE: SecurityPosture = {
  patchManagement: 'moderate',
  accessControls: 'moderate',
  networkSegmentation: true,
  mfaEnabled: true,
  backupsTested: false,
  incidentResponsePlan: true,
  securityTraining: true,
  vulnerabilityScanningFrequency: 'weekly',
  dataClassification: false,
  encryptionAtRest: true,
  encryptionInTransit: true,
  loggingAndMonitoring: 'partial',
  thirdPartyRiskManagement: false,
};

describe('Milestone 20: Compliance Autopilot', () => {
  // ─── Essential Eight ─────────────────────────────────────────

  it('Beast 20.1 — should assess Essential Eight with 8 controls', () => {
    const e8 = service.getEssentialEightStatus('org-001', STRONG_POSTURE);

    expect(e8.organisationId).toBe('org-001');
    expect(e8.controls).toHaveLength(8);
    expect(e8.overallMaturity).toBeGreaterThanOrEqual(0);
    expect(e8.overallMaturity).toBeLessThanOrEqual(3);
  });

  it('Beast 20.2 — Essential Eight maturity levels should be 0-3', () => {
    const e8 = service.getEssentialEightStatus('org-001', MODERATE_POSTURE);

    for (const control of e8.controls) {
      expect(control.maturityLevel).toBeGreaterThanOrEqual(0);
      expect(control.maturityLevel).toBeLessThanOrEqual(3);
      expect(control.targetLevel).toBe(3);
    }
  });

  it('Beast 20.3 — strong posture should score higher than weak posture', () => {
    const strong = service.getEssentialEightStatus('org-strong', STRONG_POSTURE);
    const weak = service.getEssentialEightStatus('org-weak', WEAK_POSTURE);

    expect(strong.overallMaturity).toBeGreaterThan(weak.overallMaturity);
  });

  // ─── ISO 27001 ───────────────────────────────────────────────

  it('Beast 20.4 — should assess ISO 27001 with Annex A controls', () => {
    const assessment = service.runFullAssessment('org-001', STRONG_POSTURE, ['iso-27001']);

    expect(assessment.frameworks.iso27001).toBeDefined();
    expect(assessment.frameworks.iso27001!.controls.length).toBeGreaterThan(0);
    expect(assessment.frameworks.iso27001!.compliancePercentage).toBeGreaterThanOrEqual(0);
    expect(assessment.frameworks.iso27001!.compliancePercentage).toBeLessThanOrEqual(100);
  });

  it('Beast 20.5 — strong posture should have higher ISO 27001 compliance', () => {
    const strong = service.runFullAssessment('org-s', STRONG_POSTURE, ['iso-27001']);
    const weak = service.runFullAssessment('org-w', WEAK_POSTURE, ['iso-27001']);

    expect(strong.frameworks.iso27001!.compliancePercentage)
      .toBeGreaterThan(weak.frameworks.iso27001!.compliancePercentage);
  });

  // ─── APRA CPS 234 ───────────────────────────────────────────

  it('Beast 20.6 — should assess APRA CPS 234 requirements', () => {
    const assessment = service.runFullAssessment('org-fin', MODERATE_POSTURE, ['apra-cps-234']);

    expect(assessment.frameworks.apraCps234).toBeDefined();
    expect(assessment.frameworks.apraCps234!.requirements.length).toBeGreaterThanOrEqual(10);
    expect(['compliant', 'partially_compliant', 'non_compliant'])
      .toContain(assessment.frameworks.apraCps234!.overallStatus);
  });

  // ─── NDB Readiness ───────────────────────────────────────────

  it('Beast 20.7 — should assess Privacy Act NDB readiness', () => {
    const assessment = service.runFullAssessment('org-001', MODERATE_POSTURE, ['ndb']);

    expect(assessment.frameworks.ndbReadiness).toBeDefined();
    expect(assessment.frameworks.ndbReadiness!.checks.length).toBeGreaterThanOrEqual(5);
    expect(['ready', 'partially_ready', 'not_ready'])
      .toContain(assessment.frameworks.ndbReadiness!.overallReadiness);
  });

  // ─── Full Assessment ─────────────────────────────────────────

  it('Beast 20.8 — should run full assessment across all frameworks', () => {
    const assessment = service.runFullAssessment('org-full', MODERATE_POSTURE);

    expect(assessment.frameworks.essentialEight).toBeDefined();
    expect(assessment.frameworks.iso27001).toBeDefined();
    expect(assessment.frameworks.apraCps234).toBeDefined();
    expect(assessment.frameworks.ndbReadiness).toBeDefined();
    expect(assessment.overallScore).toBeGreaterThanOrEqual(0);
    expect(assessment.overallScore).toBeLessThanOrEqual(100);
    expect(assessment.summary.length).toBeGreaterThan(20);
  });

  // ─── Gap Analysis ────────────────────────────────────────────

  it('Beast 20.9 — should generate gap analysis with prioritised gaps', () => {
    const gaps = service.getGapAnalysis('org-gaps', MODERATE_POSTURE);

    expect(gaps.organisationId).toBe('org-gaps');
    expect(gaps.totalGaps).toBeGreaterThan(0);
    expect(gaps.gaps.length).toBe(gaps.totalGaps);

    // Gaps should be sorted by priority
    const priorityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    for (let i = 1; i < gaps.gaps.length; i++) {
      expect(priorityOrder[gaps.gaps[i - 1].priority])
        .toBeLessThanOrEqual(priorityOrder[gaps.gaps[i].priority]);
    }
  });

  it('Beast 20.10 — weak posture should have more gaps than strong posture', () => {
    const weakGaps = service.getGapAnalysis('org-weak', WEAK_POSTURE);
    const strongGaps = service.getGapAnalysis('org-strong', STRONG_POSTURE);

    expect(weakGaps.totalGaps).toBeGreaterThan(strongGaps.totalGaps);
  });

  it('Beast 20.11 — gap analysis should include remediation recommendations', () => {
    const gaps = service.getGapAnalysis('org-001', WEAK_POSTURE);

    for (const gap of gaps.gaps) {
      expect(gap.remediation.length).toBeGreaterThan(0);
      expect(gap.estimatedEffort.length).toBeGreaterThan(0);
      expect(gap.framework.length).toBeGreaterThan(0);
      expect(['critical', 'high', 'medium', 'low']).toContain(gap.priority);
    }
  });

  // ─── Report Generation ───────────────────────────────────────

  it('Beast 20.12 — should generate compliance report', () => {
    const report = service.generateComplianceReport('org-report', MODERATE_POSTURE);

    expect(report.organisationId).toBe('org-report');
    expect(report.title).toContain('org-report');
    expect(report.executiveSummary.length).toBeGreaterThan(50);
    expect(report.assessment).toBeDefined();
    expect(report.gapAnalysis).toBeDefined();
    expect(report.recommendations.length).toBeGreaterThan(0);
  });

  it('Beast 20.13 — report should include executive summary with key metrics', () => {
    const report = service.generateComplianceReport('org-exec', WEAK_POSTURE);

    expect(report.executiveSummary).toContain('compliance');
    expect(report.executiveSummary).toContain('%');
    expect(report.gapAnalysis.criticalGaps).toBeGreaterThan(0);
  });

  // ─── Framework Listing ───────────────────────────────────────

  it('Beast 20.14 — should list all supported frameworks', () => {
    const frameworks = service.listFrameworks();

    expect(frameworks.length).toBe(4);

    const ids = frameworks.map((f) => f.id);
    expect(ids).toContain('essential-eight');
    expect(ids).toContain('iso-27001');
    expect(ids).toContain('apra-cps-234');
    expect(ids).toContain('ndb');

    for (const fw of frameworks) {
      expect(fw.name.length).toBeGreaterThan(0);
      expect(fw.description.length).toBeGreaterThan(0);
      expect(fw.controlCount).toBeGreaterThan(0);
    }
  });
});
