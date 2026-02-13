/**
 * Milestone 20: Compliance Autopilot — Types
 */

export interface ComplianceFramework {
  id: string;
  name: string;
  version: string;
  description: string;
  controlCount: number;
}

export type EssentialEightMaturity = 0 | 1 | 2 | 3;

export interface EssentialEightControl {
  name: string;
  maturityLevel: EssentialEightMaturity;
  targetLevel: EssentialEightMaturity;
  findings: string[];
  recommendations: string[];
}

export interface EssentialEightAssessment {
  organisationId: string;
  assessedAt: string;
  overallMaturity: EssentialEightMaturity;
  controls: EssentialEightControl[];
}

export interface Iso27001Control {
  controlId: string;
  controlName: string;
  annexSection: string;
  status: 'compliant' | 'partially_compliant' | 'non_compliant' | 'not_applicable';
  findings: string[];
  recommendations: string[];
}

export interface Iso27001Assessment {
  organisationId: string;
  assessedAt: string;
  compliancePercentage: number;
  controls: Iso27001Control[];
}

export interface ApraCps234Check {
  requirementId: string;
  requirementName: string;
  category: string;
  status: 'met' | 'partially_met' | 'not_met' | 'not_applicable';
  findings: string[];
  recommendations: string[];
}

export interface ApraCps234Assessment {
  organisationId: string;
  assessedAt: string;
  overallStatus: 'compliant' | 'partially_compliant' | 'non_compliant';
  requirements: ApraCps234Check[];
}

export interface NdbReadinessCheck {
  area: string;
  status: 'ready' | 'partially_ready' | 'not_ready';
  findings: string[];
  recommendations: string[];
}

export interface NdbReadinessAssessment {
  organisationId: string;
  assessedAt: string;
  overallReadiness: 'ready' | 'partially_ready' | 'not_ready';
  checks: NdbReadinessCheck[];
}

export interface ComplianceAssessment {
  organisationId: string;
  assessedAt: string;
  frameworks: {
    essentialEight?: EssentialEightAssessment;
    iso27001?: Iso27001Assessment;
    apraCps234?: ApraCps234Assessment;
    ndbReadiness?: NdbReadinessAssessment;
  };
  overallScore: number; // 0-100
  summary: string;
}

export interface ComplianceGap {
  framework: string;
  controlId: string;
  controlName: string;
  currentState: string;
  requiredState: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  remediation: string;
  estimatedEffort: string;
}

export interface GapAnalysis {
  organisationId: string;
  analysedAt: string;
  totalGaps: number;
  criticalGaps: number;
  gaps: ComplianceGap[];
}

export interface ComplianceReport {
  organisationId: string;
  generatedAt: string;
  title: string;
  executiveSummary: string;
  assessment: ComplianceAssessment;
  gapAnalysis: GapAnalysis;
  recommendations: string[];
  reportFormat: 'pdf' | 'json';
}

export interface SecurityPosture {
  patchManagement: 'strong' | 'moderate' | 'weak';
  accessControls: 'strong' | 'moderate' | 'weak';
  networkSegmentation: boolean;
  mfaEnabled: boolean;
  backupsTested: boolean;
  incidentResponsePlan: boolean;
  securityTraining: boolean;
  vulnerabilityScanningFrequency: 'continuous' | 'weekly' | 'monthly' | 'quarterly' | 'never';
  dataClassification: boolean;
  encryptionAtRest: boolean;
  encryptionInTransit: boolean;
  loggingAndMonitoring: 'comprehensive' | 'partial' | 'minimal' | 'none';
  thirdPartyRiskManagement: boolean;
}
