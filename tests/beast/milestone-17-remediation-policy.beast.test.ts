/**
 * Beast Tests — Milestone 17: Autonomous Remediation Policy Framework
 *
 * Tests all 4 remediation tiers, approval workflow, YAML loading,
 * emergency halt, and audit trail.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import * as service from '../../src/services/remediation-policy.js';

beforeEach(() => {
  service._resetState();
});

describe('Milestone 17: Autonomous Remediation Policy Framework', () => {
  // ─── Policy CRUD ─────────────────────────────────────────────

  it('Beast 17.1 — should create a new remediation policy', () => {
    const policy = service.createOrUpdatePolicy({
      findingType: 'missing_header',
      tier: 'AUTO',
      description: 'Add missing security headers',
      remediationAction: 'Add CSP, X-Frame-Options headers',
    });

    expect(policy.id).toBeDefined();
    expect(policy.findingType).toBe('missing_header');
    expect(policy.tier).toBe('AUTO');
    expect(policy.enabled).toBe(true);
  });

  it('Beast 17.2 — should update an existing policy for the same finding type', () => {
    service.createOrUpdatePolicy({
      findingType: 'xss',
      tier: 'AUTO',
      description: 'XSS fix v1',
      remediationAction: 'Sanitise input',
    });

    const updated = service.createOrUpdatePolicy({
      findingType: 'xss',
      tier: 'SUPERVISED',
      description: 'XSS fix v2',
      remediationAction: 'Sanitise and encode output',
    });

    expect(updated.tier).toBe('SUPERVISED');
    expect(updated.description).toBe('XSS fix v2');
    expect(service.listPolicies()).toHaveLength(1);
  });

  it('Beast 17.3 — should list all policies', () => {
    service.createOrUpdatePolicy({ findingType: 'a', tier: 'AUTO', description: 'A', remediationAction: 'Fix A' });
    service.createOrUpdatePolicy({ findingType: 'b', tier: 'SUPERVISED', description: 'B', remediationAction: 'Fix B' });
    service.createOrUpdatePolicy({ findingType: 'c', tier: 'PROHIBITED', description: 'C', remediationAction: 'Fix C' });

    expect(service.listPolicies()).toHaveLength(3);
  });

  // ─── YAML Loading ────────────────────────────────────────────

  it('Beast 17.4 — should load policies from YAML content', () => {
    const yamlContent = `
policies:
  - findingType: missing_header
    tier: AUTO
    description: Add missing headers
    remediationAction: Configure headers
  - findingType: dns_misconfiguration
    tier: PROHIBITED
    description: DNS changes blocked
    remediationAction: Manual change request
`;

    const policies = service.loadPoliciesFromYaml(yamlContent);
    expect(policies).toHaveLength(2);
    expect(policies[0].tier).toBe('AUTO');
    expect(policies[1].tier).toBe('PROHIBITED');
  });

  it('Beast 17.5 — should reject invalid YAML content', () => {
    expect(() => service.loadPoliciesFromYaml('not valid yaml content: [}')).toThrow();
  });

  // ─── AUTO Tier ───────────────────────────────────────────────

  it('Beast 17.6 — AUTO tier should execute immediately without approval', () => {
    service.createOrUpdatePolicy({
      findingType: 'missing_header',
      tier: 'AUTO',
      description: 'Auto-fix headers',
      remediationAction: 'Add headers',
    });

    const action = service.triggerRemediation({
      findingType: 'missing_header',
      description: 'Missing CSP header on prod',
    });

    expect(action.status).toBe('executed');
    expect(action.executedAt).toBeDefined();
    expect(action.tier).toBe('AUTO');
  });

  // ─── SUPERVISED Tier ─────────────────────────────────────────

  it('Beast 17.7 — SUPERVISED tier should execute with logging for post-hoc review', () => {
    service.createOrUpdatePolicy({
      findingType: 'weak_crypto',
      tier: 'SUPERVISED',
      description: 'Upgrade crypto',
      remediationAction: 'Replace TLS config',
    });

    const action = service.triggerRemediation({
      findingType: 'weak_crypto',
      description: 'TLS 1.0 detected',
    });

    expect(action.status).toBe('executed');
    expect(action.tier).toBe('SUPERVISED');

    // Should be in audit log
    const audit = service.getAuditLog();
    const supervised = audit.find((e) => e.event === 'supervised_executed');
    expect(supervised).toBeDefined();
  });

  // ─── APPROVAL_REQUIRED Tier ──────────────────────────────────

  it('Beast 17.8 — APPROVAL_REQUIRED tier should queue for approval with token', () => {
    service.createOrUpdatePolicy({
      findingType: 'auth_bypass',
      tier: 'APPROVAL_REQUIRED',
      description: 'Auth fix needs approval',
      remediationAction: 'Patch auth logic',
    });

    const action = service.triggerRemediation({
      findingType: 'auth_bypass',
      description: 'Auth bypass found in login',
    });

    expect(action.status).toBe('pending');
    expect(action.tier).toBe('APPROVAL_REQUIRED');
    expect(action.approvalToken).toBeDefined();
    expect(action.approvalTokenExpiresAt).toBeDefined();
  });

  it('Beast 17.9 — should approve a queued action with valid token', () => {
    service.createOrUpdatePolicy({
      findingType: 'sql_injection',
      tier: 'APPROVAL_REQUIRED',
      description: 'SQLi fix',
      remediationAction: 'Parameterise queries',
    });

    const action = service.triggerRemediation({
      findingType: 'sql_injection',
      description: 'SQLi in search',
    });

    const approved = service.approveAction(
      action.id,
      action.approvalToken!,
      'security-lead@example.com',
    );

    expect(approved.status).toBe('executed');
    expect(approved.approvedBy).toBe('security-lead@example.com');
    expect(approved.executedAt).toBeDefined();
  });

  it('Beast 17.10 — should reject approval with invalid token', () => {
    service.createOrUpdatePolicy({
      findingType: 'auth_bypass',
      tier: 'APPROVAL_REQUIRED',
      description: 'Auth fix',
      remediationAction: 'Patch auth',
    });

    const action = service.triggerRemediation({
      findingType: 'auth_bypass',
      description: 'Bypass found',
    });

    expect(() =>
      service.approveAction(action.id, 'wrong-token', 'attacker@evil.com'),
    ).toThrow('Invalid approval token');
  });

  // ─── PROHIBITED Tier ─────────────────────────────────────────

  it('Beast 17.11 — PROHIBITED tier should reject remediation', () => {
    service.createOrUpdatePolicy({
      findingType: 'dns_misconfiguration',
      tier: 'PROHIBITED',
      description: 'DNS changes blocked',
      remediationAction: 'Manual only',
    });

    const action = service.triggerRemediation({
      findingType: 'dns_misconfiguration',
      description: 'DNS zone transfer enabled',
    });

    expect(action.status).toBe('rejected');
    expect(action.tier).toBe('PROHIBITED');
  });

  // ─── Emergency Halt ──────────────────────────────────────────

  it('Beast 17.12 — emergency halt should block all new remediations', () => {
    service.createOrUpdatePolicy({
      findingType: 'xss',
      tier: 'AUTO',
      description: 'XSS fix',
      remediationAction: 'Sanitise',
    });

    service.emergencyHalt('ciso@company.com', 'Active incident in progress');

    const action = service.triggerRemediation({
      findingType: 'xss',
      description: 'XSS found',
    });

    expect(action.status).toBe('halted');
    expect(service.getHaltState().halted).toBe(true);
    expect(service.getHaltState().haltedBy).toBe('ciso@company.com');
  });

  it('Beast 17.13 — emergency halt should halt all pending actions', () => {
    service.createOrUpdatePolicy({
      findingType: 'auth_bypass',
      tier: 'APPROVAL_REQUIRED',
      description: 'Auth fix',
      remediationAction: 'Patch',
    });

    const pending = service.triggerRemediation({
      findingType: 'auth_bypass',
      description: 'Pending action',
    });
    expect(pending.status).toBe('pending');

    service.emergencyHalt('ciso@company.com', 'Halt everything');

    const halted = service.getAction(pending.id);
    expect(halted?.status).toBe('halted');
  });

  it('Beast 17.14 — should lift emergency halt', () => {
    service.emergencyHalt('ciso@company.com', 'Test halt');
    expect(service.getHaltState().halted).toBe(true);

    service.liftHalt();
    expect(service.getHaltState().halted).toBe(false);
  });

  // ─── Audit Trail ─────────────────────────────────────────────

  it('Beast 17.15 — audit trail should record all actions', () => {
    service.createOrUpdatePolicy({
      findingType: 'missing_header',
      tier: 'AUTO',
      description: 'Fix headers',
      remediationAction: 'Add headers',
    });

    service.triggerRemediation({
      findingType: 'missing_header',
      description: 'Missing header',
    });

    const audit = service.getAuditLog();
    expect(audit.length).toBeGreaterThanOrEqual(2); // policy_created + auto_executed
    expect(audit.some((e) => e.event === 'policy_created')).toBe(true);
    expect(audit.some((e) => e.event === 'auto_executed')).toBe(true);
  });

  it('Beast 17.16 — audit trail should record emergency halt events', () => {
    service.emergencyHalt('admin@corp.com', 'Security incident');

    const audit = service.getAuditLog();
    const haltEntry = audit.find((e) => e.event === 'emergency_halt_activated');
    expect(haltEntry).toBeDefined();
    expect(haltEntry!.actor).toBe('admin@corp.com');
  });
});
