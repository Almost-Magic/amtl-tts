/**
 * Milestone 17: Autonomous Remediation Policy Framework — Types
 */

export type RemediationTier = 'AUTO' | 'SUPERVISED' | 'APPROVAL_REQUIRED' | 'PROHIBITED';

export interface RemediationPolicy {
  id: string;
  findingType: string;
  tier: RemediationTier;
  description: string;
  remediationAction: string;
  createdAt: string;
  updatedAt: string;
  enabled: boolean;
}

export interface RemediationAction {
  id: string;
  policyId: string;
  findingType: string;
  tier: RemediationTier;
  description: string;
  status: 'pending' | 'approved' | 'executed' | 'rejected' | 'halted';
  approvalToken?: string;
  approvalTokenExpiresAt?: string;
  approvedBy?: string;
  executedAt?: string;
  createdAt: string;
  notificationEmail?: string;
}

export interface AuditEntry {
  id: string;
  actionId: string;
  event: string;
  details: string;
  timestamp: string;
  actor: string;
}

export interface PolicyDefinitionYaml {
  policies: Array<{
    findingType: string;
    tier: RemediationTier;
    description: string;
    remediationAction: string;
  }>;
}

export interface HaltState {
  halted: boolean;
  haltedAt?: string;
  haltedBy?: string;
  reason?: string;
}
