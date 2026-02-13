/**
 * Milestone 17: Autonomous Remediation Policy Framework — Service
 */
import yaml from 'js-yaml';
import { generateId, generateToken } from '../utils/id.js';
import { clock } from '../utils/clock.js';
import type {
  RemediationPolicy,
  RemediationAction,
  AuditEntry,
  RemediationTier,
  PolicyDefinitionYaml,
  HaltState,
} from '../models/remediation-policy.js';

// In-memory stores
const policies: Map<string, RemediationPolicy> = new Map();
const actions: Map<string, RemediationAction> = new Map();
const auditLog: AuditEntry[] = [];
let haltState: HaltState = { halted: false };

const APPROVAL_TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

function addAudit(actionId: string, event: string, details: string, actor: string): void {
  auditLog.push({
    id: generateId(),
    actionId,
    event,
    details,
    timestamp: clock.isoNow(),
    actor,
  });
}

export function listPolicies(): RemediationPolicy[] {
  return Array.from(policies.values());
}

export function createOrUpdatePolicy(input: {
  findingType: string;
  tier: RemediationTier;
  description: string;
  remediationAction: string;
}): RemediationPolicy {
  // Check if a policy for this finding type already exists
  const existing = Array.from(policies.values()).find(
    (p) => p.findingType === input.findingType,
  );

  if (existing) {
    existing.tier = input.tier;
    existing.description = input.description;
    existing.remediationAction = input.remediationAction;
    existing.updatedAt = clock.isoNow();
    addAudit(existing.id, 'policy_updated', `Policy updated for ${input.findingType}`, 'system');
    return existing;
  }

  const policy: RemediationPolicy = {
    id: generateId(),
    findingType: input.findingType,
    tier: input.tier,
    description: input.description,
    remediationAction: input.remediationAction,
    createdAt: clock.isoNow(),
    updatedAt: clock.isoNow(),
    enabled: true,
  };
  policies.set(policy.id, policy);
  addAudit(policy.id, 'policy_created', `Policy created for ${input.findingType}`, 'system');
  return policy;
}

export function loadPoliciesFromYaml(yamlContent: string): RemediationPolicy[] {
  const parsed = yaml.load(yamlContent) as PolicyDefinitionYaml;
  if (!parsed?.policies || !Array.isArray(parsed.policies)) {
    throw new Error('Invalid YAML: expected a "policies" array');
  }

  const results: RemediationPolicy[] = [];
  for (const entry of parsed.policies) {
    const policy = createOrUpdatePolicy({
      findingType: entry.findingType,
      tier: entry.tier,
      description: entry.description,
      remediationAction: entry.remediationAction,
    });
    results.push(policy);
  }
  return results;
}

export function triggerRemediation(input: {
  findingType: string;
  description: string;
  notificationEmail?: string;
}): RemediationAction {
  if (haltState.halted) {
    const action: RemediationAction = {
      id: generateId(),
      policyId: '',
      findingType: input.findingType,
      tier: 'PROHIBITED',
      description: input.description,
      status: 'halted',
      createdAt: clock.isoNow(),
    };
    actions.set(action.id, action);
    addAudit(action.id, 'action_halted', 'Emergency halt is active — action blocked', 'system');
    return action;
  }

  const policy = Array.from(policies.values()).find(
    (p) => p.findingType === input.findingType && p.enabled,
  );

  if (!policy) {
    throw new Error(`No policy found for finding type: ${input.findingType}`);
  }

  const action: RemediationAction = {
    id: generateId(),
    policyId: policy.id,
    findingType: input.findingType,
    tier: policy.tier,
    description: input.description,
    status: 'pending',
    createdAt: clock.isoNow(),
    notificationEmail: input.notificationEmail,
  };

  switch (policy.tier) {
    case 'AUTO': {
      action.status = 'executed';
      action.executedAt = clock.isoNow();
      addAudit(action.id, 'auto_executed', `Automatically remediated: ${policy.remediationAction}`, 'system');
      break;
    }
    case 'SUPERVISED': {
      action.status = 'executed';
      action.executedAt = clock.isoNow();
      addAudit(action.id, 'supervised_executed', `Executed with post-hoc review: ${policy.remediationAction}`, 'system');
      break;
    }
    case 'APPROVAL_REQUIRED': {
      const token = generateToken();
      action.status = 'pending';
      action.approvalToken = token;
      action.approvalTokenExpiresAt = new Date(
        clock.now().getTime() + APPROVAL_TOKEN_TTL_MS,
      ).toISOString();
      addAudit(action.id, 'approval_requested', `Queued for approval: ${policy.remediationAction}`, 'system');
      break;
    }
    case 'PROHIBITED': {
      action.status = 'rejected';
      addAudit(action.id, 'prohibited', `Remediation prohibited by policy for: ${input.findingType}`, 'system');
      break;
    }
  }

  actions.set(action.id, action);
  return action;
}

export function approveAction(actionId: string, approvalToken: string, approvedBy: string): RemediationAction {
  const action = actions.get(actionId);
  if (!action) {
    throw new Error(`Action not found: ${actionId}`);
  }

  if (haltState.halted) {
    throw new Error('Emergency halt is active — cannot approve actions');
  }

  if (action.status !== 'pending') {
    throw new Error(`Action is not pending approval (current status: ${action.status})`);
  }

  if (action.tier !== 'APPROVAL_REQUIRED') {
    throw new Error(`Action tier ${action.tier} does not require approval`);
  }

  if (action.approvalToken !== approvalToken) {
    throw new Error('Invalid approval token');
  }

  if (action.approvalTokenExpiresAt && new Date(action.approvalTokenExpiresAt) < clock.now()) {
    throw new Error('Approval token has expired');
  }

  action.status = 'approved';
  action.approvedBy = approvedBy;
  action.executedAt = clock.isoNow();
  action.status = 'executed';

  addAudit(action.id, 'approved_and_executed', `Approved by ${approvedBy} and executed`, approvedBy);
  return action;
}

export function emergencyHalt(haltedBy: string, reason: string): HaltState {
  haltState = {
    halted: true,
    haltedAt: clock.isoNow(),
    haltedBy,
    reason,
  };

  // Halt all pending actions
  for (const action of actions.values()) {
    if (action.status === 'pending') {
      action.status = 'halted';
      addAudit(action.id, 'emergency_halted', `Halted by ${haltedBy}: ${reason}`, haltedBy);
    }
  }

  addAudit('system', 'emergency_halt_activated', `Emergency halt by ${haltedBy}: ${reason}`, haltedBy);
  return haltState;
}

export function getHaltState(): HaltState {
  return { ...haltState };
}

export function liftHalt(): HaltState {
  haltState = { halted: false };
  addAudit('system', 'emergency_halt_lifted', 'Emergency halt lifted', 'system');
  return haltState;
}

export function getAuditLog(): AuditEntry[] {
  return [...auditLog];
}

export function getAction(actionId: string): RemediationAction | undefined {
  return actions.get(actionId);
}

export function listActions(): RemediationAction[] {
  return Array.from(actions.values());
}

/** Reset all state — used in tests */
export function _resetState(): void {
  policies.clear();
  actions.clear();
  auditLog.length = 0;
  haltState = { halted: false };
}
