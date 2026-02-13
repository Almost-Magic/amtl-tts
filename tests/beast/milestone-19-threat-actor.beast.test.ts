/**
 * Beast Tests — Milestone 19: Threat Actor Profiler
 *
 * Tests MITRE ATT&CK mapping, threat actor identification,
 * kill chain analysis, relevance scoring, and executive briefings.
 */
import { describe, it, expect } from 'vitest';
import * as service from '../../src/services/threat-actor.js';
import type { Vulnerability } from '../../src/models/shared.js';

const SAMPLE_VULNS: Vulnerability[] = [
  {
    id: 'vuln-001', title: 'SQL Injection in search', severity: 'critical', cvssScore: 9.8,
    cveId: 'CVE-2025-1234', findingType: 'sql_injection', description: 'SQLi in search endpoint',
    affectedAsset: 'api.example.com', discoveredAt: '2025-01-01', exposureDays: 30,
    mitreTechniques: ['T1190'],
  },
  {
    id: 'vuln-002', title: 'Authentication bypass', severity: 'critical', cvssScore: 9.1,
    findingType: 'auth_bypass', description: 'Auth bypass in admin panel',
    affectedAsset: 'admin.example.com', discoveredAt: '2025-01-15', exposureDays: 15,
  },
  {
    id: 'vuln-003', title: 'Privilege escalation', severity: 'high', cvssScore: 7.5,
    findingType: 'privilege_escalation', description: 'Local privesc via service account',
    affectedAsset: 'internal-server', discoveredAt: '2025-02-01', exposureDays: 10,
  },
  {
    id: 'vuln-004', title: 'Weak TLS configuration', severity: 'medium', cvssScore: 5.3,
    findingType: 'weak_crypto', description: 'TLS 1.0 enabled on web server',
    affectedAsset: 'web.example.com', discoveredAt: '2025-01-20', exposureDays: 20,
  },
  {
    id: 'vuln-005', title: 'Default credentials on admin panel', severity: 'high', cvssScore: 8.1,
    findingType: 'default_credentials', description: 'Default admin/admin credentials',
    affectedAsset: 'router.internal', discoveredAt: '2025-02-05', exposureDays: 5,
  },
  {
    id: 'vuln-006', title: 'SSRF in image processing', severity: 'high', cvssScore: 7.2,
    findingType: 'ssrf', description: 'Server-side request forgery',
    affectedAsset: 'api.example.com', discoveredAt: '2025-01-25', exposureDays: 15,
  },
];

const MINIMAL_VULNS: Vulnerability[] = [
  {
    id: 'vuln-low-1', title: 'Missing X-Frame-Options', severity: 'low', cvssScore: 2.0,
    findingType: 'missing_header', description: 'X-Frame-Options header missing',
    affectedAsset: 'www.example.com', discoveredAt: '2025-03-01', exposureDays: 3,
  },
];

describe('Milestone 19: Threat Actor Profiler', () => {
  // ─── MITRE ATT&CK Mapping ───────────────────────────────────

  it('Beast 19.1 — should map vulnerabilities to MITRE ATT&CK techniques', () => {
    const mappings = service.getMitreMapping(SAMPLE_VULNS);

    expect(mappings.length).toBeGreaterThanOrEqual(5);

    const techniqueIds = mappings.map((m) => m.techniqueId);
    expect(techniqueIds).toContain('T1190'); // sql_injection + ssrf
    expect(techniqueIds).toContain('T1078'); // auth_bypass
    expect(techniqueIds).toContain('T1068'); // privilege_escalation
  });

  it('Beast 19.2 — MITRE mappings should include tactic information', () => {
    const mappings = service.getMitreMapping(SAMPLE_VULNS);

    for (const mapping of mappings) {
      expect(mapping.tacticId).toBeDefined();
      expect(mapping.tacticName).toBeDefined();
      expect(mapping.techniqueId).toMatch(/^T\d+/);
      expect(mapping.vulnerabilityId).toBeDefined();
    }
  });

  it('Beast 19.3 — should handle vulnerabilities with embedded MITRE techniques', () => {
    const vulnWithTechniques: Vulnerability[] = [
      {
        id: 'vuln-embedded', title: 'RCE', severity: 'critical', cvssScore: 10,
        findingType: 'rce', description: 'Remote code execution',
        affectedAsset: 'server', discoveredAt: '2025-01-01', exposureDays: 1,
        mitreTechniques: ['T1059'],
      },
    ];

    const mappings = service.getMitreMapping(vulnWithTechniques);
    const techniqueIds = mappings.map((m) => m.techniqueId);
    expect(techniqueIds).toContain('T1203'); // from findingType rce
    expect(techniqueIds).toContain('T1059'); // from mitreTechniques array
  });

  // ─── Threat Actor Identification ─────────────────────────────

  it('Beast 19.4 — should identify relevant threat actors for finance + Australia', () => {
    const profile = service.profileOrganisation('org-fin', SAMPLE_VULNS, 'finance', 'Australia');

    expect(profile.identifiedActors.length).toBeGreaterThan(0);

    // Actors should be sorted by relevance score descending
    for (let i = 1; i < profile.identifiedActors.length; i++) {
      expect(profile.identifiedActors[i - 1].relevanceScore)
        .toBeGreaterThanOrEqual(profile.identifiedActors[i].relevanceScore);
    }
  });

  it('Beast 19.5 — relevance scores should be between 0 and 100', () => {
    const profile = service.profileOrganisation('org-001', SAMPLE_VULNS, 'technology', 'Australia');

    for (const actor of profile.identifiedActors) {
      expect(actor.relevanceScore).toBeGreaterThanOrEqual(0);
      expect(actor.relevanceScore).toBeLessThanOrEqual(100);
    }
  });

  it('Beast 19.6 — financial sector should score FIN7 highly', () => {
    const profile = service.profileOrganisation('org-fin', SAMPLE_VULNS, 'finance', 'Australia');

    const fin7 = profile.identifiedActors.find((a) => a.name.includes('FIN7'));
    expect(fin7).toBeDefined();
    expect(fin7!.relevanceScore).toBeGreaterThanOrEqual(30);
  });

  it('Beast 19.7 — minimal vulnerabilities should produce lower relevance scores', () => {
    const fullProfile = service.profileOrganisation('org-full', SAMPLE_VULNS, 'finance', 'Australia');
    const minProfile = service.profileOrganisation('org-min', MINIMAL_VULNS, 'finance', 'Australia');

    const fullTopScore = fullProfile.identifiedActors[0].relevanceScore;
    const minTopScore = minProfile.identifiedActors[0].relevanceScore;

    expect(fullTopScore).toBeGreaterThan(minTopScore);
  });

  // ─── Kill Chain Analysis ─────────────────────────────────────

  it('Beast 19.8 — should construct kill chain with 7 phases', () => {
    const killChain = service.getKillChainAnalysis('org-001', SAMPLE_VULNS);

    expect(killChain.phases).toHaveLength(7);
    expect(killChain.phases[0].phase).toBe('Reconnaissance');
    expect(killChain.phases[6].phase).toBe('Actions on Objectives');

    // Phases should be in order
    for (let i = 1; i < killChain.phases.length; i++) {
      expect(killChain.phases[i].order).toBeGreaterThan(killChain.phases[i - 1].order);
    }
  });

  it('Beast 19.9 — kill chain should identify exposed phases from vulnerability data', () => {
    const killChain = service.getKillChainAnalysis('org-001', SAMPLE_VULNS);

    // With sql_injection, auth_bypass, etc. we expect some exposed phases
    const exposedPhases = killChain.phases.filter((p) => p.currentExposure !== 'mitigated');
    expect(exposedPhases.length).toBeGreaterThan(0);
  });

  it('Beast 19.10 — kill chain should have overall risk rating', () => {
    const killChain = service.getKillChainAnalysis('org-001', SAMPLE_VULNS);

    expect(['critical', 'high', 'medium', 'low']).toContain(killChain.overallRisk);
    expect(killChain.completePaths).toBeGreaterThanOrEqual(0);
    expect(killChain.mostLikelyPath.length).toBeGreaterThan(0);
  });

  // ─── Executive Briefing ──────────────────────────────────────

  it('Beast 19.11 — should generate executive briefing', () => {
    const briefing = service.getExecutiveBriefing('org-001', SAMPLE_VULNS, 'finance', 'Australia');

    expect(briefing.organisationId).toBe('org-001');
    expect(briefing.summary.length).toBeGreaterThan(50);
    expect(briefing.topThreats.length).toBeGreaterThan(0);
    expect(briefing.recommendations.length).toBeGreaterThan(0);
  });

  it('Beast 19.12 — executive briefing should contain actionable recommendations', () => {
    const briefing = service.getExecutiveBriefing('org-001', SAMPLE_VULNS, 'technology', 'Australia');

    for (const rec of briefing.recommendations) {
      expect(rec.length).toBeGreaterThan(10);
    }

    // Top threats should have likelihood ratings
    for (const threat of briefing.topThreats) {
      expect(['High', 'Medium', 'Low']).toContain(threat.likelihood);
      expect(threat.relevanceScore).toBeGreaterThan(0);
    }
  });

  // ─── Full Profile ────────────────────────────────────────────

  it('Beast 19.13 — full profile should contain all components', () => {
    const profile = service.profileOrganisation('org-complete', SAMPLE_VULNS, 'healthcare', 'Australia');

    expect(profile.organisationId).toBe('org-complete');
    expect(profile.generatedAt).toBeDefined();
    expect(profile.mitreMappings.length).toBeGreaterThan(0);
    expect(profile.identifiedActors.length).toBeGreaterThan(0);
    expect(profile.killChain).toBeDefined();
    expect(profile.killChain.phases).toHaveLength(7);
    expect(profile.executiveBriefing.length).toBeGreaterThan(0);
  });
});
