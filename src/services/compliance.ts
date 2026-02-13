/**
 * Milestone 20: Compliance Autopilot — Service
 *
 * Automated compliance checking for Australian frameworks:
 * Essential Eight, ISO 27001, APRA CPS 234, Privacy Act NDB.
 */
import { clock } from '../utils/clock.js';
import type {
  ComplianceFramework,
  EssentialEightAssessment,
  EssentialEightControl,
  EssentialEightMaturity,
  Iso27001Assessment,
  Iso27001Control,
  ApraCps234Assessment,
  ApraCps234Check,
  NdbReadinessAssessment,
  NdbReadinessCheck,
  ComplianceAssessment,
  ComplianceGap,
  GapAnalysis,
  ComplianceReport,
  SecurityPosture,
} from '../models/compliance.js';

// Supported frameworks
const FRAMEWORKS: ComplianceFramework[] = [
  { id: 'essential-eight', name: 'Essential Eight', version: '2023', description: 'Australian Signals Directorate Essential Eight Maturity Model', controlCount: 8 },
  { id: 'iso-27001', name: 'ISO 27001:2022', version: '2022', description: 'International Standard for Information Security Management Systems', controlCount: 93 },
  { id: 'apra-cps-234', name: 'APRA CPS 234', version: '2019', description: 'Australian Prudential Regulation Authority — Information Security', controlCount: 12 },
  { id: 'ndb', name: 'Privacy Act NDB', version: '2018', description: 'Notifiable Data Breaches Scheme under the Privacy Act 1988', controlCount: 6 },
];

// Essential Eight controls
const ESSENTIAL_EIGHT_CONTROLS = [
  'Application Control',
  'Patch Applications',
  'Configure Microsoft Office Macro Settings',
  'User Application Hardening',
  'Restrict Administrative Privileges',
  'Patch Operating Systems',
  'Multi-Factor Authentication',
  'Regular Backups',
];

// ISO 27001 Annex A controls (representative subset)
const ISO_27001_CONTROLS: Array<{ id: string; name: string; section: string }> = [
  { id: 'A.5.1', name: 'Policies for information security', section: 'A.5 Organisational Controls' },
  { id: 'A.5.2', name: 'Information security roles and responsibilities', section: 'A.5 Organisational Controls' },
  { id: 'A.5.3', name: 'Segregation of duties', section: 'A.5 Organisational Controls' },
  { id: 'A.6.1', name: 'Screening', section: 'A.6 People Controls' },
  { id: 'A.6.2', name: 'Terms and conditions of employment', section: 'A.6 People Controls' },
  { id: 'A.7.1', name: 'Physical security perimeters', section: 'A.7 Physical Controls' },
  { id: 'A.8.1', name: 'User endpoint devices', section: 'A.8 Technological Controls' },
  { id: 'A.8.2', name: 'Privileged access rights', section: 'A.8 Technological Controls' },
  { id: 'A.8.3', name: 'Information access restriction', section: 'A.8 Technological Controls' },
  { id: 'A.8.5', name: 'Secure authentication', section: 'A.8 Technological Controls' },
  { id: 'A.8.7', name: 'Protection against malware', section: 'A.8 Technological Controls' },
  { id: 'A.8.8', name: 'Management of technical vulnerabilities', section: 'A.8 Technological Controls' },
  { id: 'A.8.9', name: 'Configuration management', section: 'A.8 Technological Controls' },
  { id: 'A.8.10', name: 'Information deletion', section: 'A.8 Technological Controls' },
  { id: 'A.8.12', name: 'Data leakage prevention', section: 'A.8 Technological Controls' },
  { id: 'A.8.15', name: 'Logging', section: 'A.8 Technological Controls' },
  { id: 'A.8.16', name: 'Monitoring activities', section: 'A.8 Technological Controls' },
  { id: 'A.8.20', name: 'Networks security', section: 'A.8 Technological Controls' },
  { id: 'A.8.24', name: 'Use of cryptography', section: 'A.8 Technological Controls' },
  { id: 'A.8.25', name: 'Secure development life cycle', section: 'A.8 Technological Controls' },
  { id: 'A.8.28', name: 'Secure coding', section: 'A.8 Technological Controls' },
];

// APRA CPS 234 requirements
const APRA_CPS234_REQUIREMENTS: Array<{ id: string; name: string; category: string }> = [
  { id: 'CPS234.1', name: 'Information security capability', category: 'Governance' },
  { id: 'CPS234.2', name: 'Policy framework', category: 'Governance' },
  { id: 'CPS234.3', name: 'Information asset identification and classification', category: 'Asset Management' },
  { id: 'CPS234.4', name: 'Implementation of controls', category: 'Controls' },
  { id: 'CPS234.5', name: 'Incident management', category: 'Incident Management' },
  { id: 'CPS234.6', name: 'Testing control effectiveness', category: 'Testing' },
  { id: 'CPS234.7', name: 'Internal audit', category: 'Audit' },
  { id: 'CPS234.8', name: 'APRA notification', category: 'Reporting' },
  { id: 'CPS234.9', name: 'Third-party arrangements', category: 'Third Party' },
  { id: 'CPS234.10', name: 'Information security roles', category: 'Governance' },
  { id: 'CPS234.11', name: 'Board oversight', category: 'Governance' },
  { id: 'CPS234.12', name: 'Systemic information security control weaknesses', category: 'Controls' },
];

// NDB readiness areas
const NDB_AREAS = [
  'Data breach response plan',
  'Breach detection capability',
  'Assessment process for eligible data breaches',
  'Notification procedures (to OAIC)',
  'Notification procedures (to affected individuals)',
  'Record-keeping of data breaches',
];

function assessEssentialEight(posture: SecurityPosture): EssentialEightAssessment {
  const controls: EssentialEightControl[] = [];

  // 1. Application Control
  controls.push(assessE8Control('Application Control', posture.accessControls === 'strong' ? 2 : posture.accessControls === 'moderate' ? 1 : 0, 3,
    posture.accessControls !== 'strong' ? ['Application control not fully implemented'] : [],
    posture.accessControls !== 'strong' ? ['Implement application whitelisting on all workstations'] : [],
  ));

  // 2. Patch Applications
  const patchLevel: EssentialEightMaturity = posture.patchManagement === 'strong' ? 3 : posture.patchManagement === 'moderate' ? 2 : 0;
  controls.push(assessE8Control('Patch Applications', patchLevel, 3,
    patchLevel < 3 ? ['Application patching cadence does not meet maturity level 3'] : [],
    patchLevel < 3 ? ['Implement automated patching within 48 hours for critical patches'] : [],
  ));

  // 3. Configure Microsoft Office Macro Settings
  const macroLevel: EssentialEightMaturity = posture.accessControls === 'strong' ? 2 : 1;
  controls.push(assessE8Control('Configure Microsoft Office Macro Settings', macroLevel, 3,
    ['Macro settings require further hardening for maturity level 3'],
    ['Block macros from the internet, only allow vetted macros in trusted locations'],
  ));

  // 4. User Application Hardening
  const hardeningLevel: EssentialEightMaturity = posture.encryptionInTransit && posture.encryptionAtRest ? 2 : 1;
  controls.push(assessE8Control('User Application Hardening', hardeningLevel, 3,
    hardeningLevel < 3 ? ['User applications not fully hardened'] : [],
    hardeningLevel < 3 ? ['Disable Flash, Java, and ads in web browsers; configure strict CSP'] : [],
  ));

  // 5. Restrict Administrative Privileges
  const adminLevel: EssentialEightMaturity = posture.accessControls === 'strong' && posture.mfaEnabled ? 3 : posture.accessControls === 'moderate' ? 1 : 0;
  controls.push(assessE8Control('Restrict Administrative Privileges', adminLevel, 3,
    adminLevel < 3 ? ['Administrative privilege restrictions insufficient'] : [],
    adminLevel < 3 ? ['Implement just-in-time administration with MFA for all privileged access'] : [],
  ));

  // 6. Patch Operating Systems
  controls.push(assessE8Control('Patch Operating Systems', patchLevel, 3,
    patchLevel < 3 ? ['OS patching cadence does not meet maturity level 3'] : [],
    patchLevel < 3 ? ['Patch operating systems within 48 hours for critical vulnerabilities'] : [],
  ));

  // 7. Multi-Factor Authentication
  const mfaLevel: EssentialEightMaturity = posture.mfaEnabled ? 2 : 0;
  controls.push(assessE8Control('Multi-Factor Authentication', mfaLevel, 3,
    !posture.mfaEnabled ? ['MFA not enabled'] : ['MFA enabled but may not cover all access points'],
    !posture.mfaEnabled ? ['Enable MFA for all users across all systems'] : ['Extend MFA to all remote access and privileged accounts using phishing-resistant methods'],
  ));

  // 8. Regular Backups
  const backupLevel: EssentialEightMaturity = posture.backupsTested ? 2 : 1;
  controls.push(assessE8Control('Regular Backups', backupLevel, 3,
    !posture.backupsTested ? ['Backup restoration not regularly tested'] : ['Backups tested but may not meet RPO/RTO requirements'],
    !posture.backupsTested ? ['Implement and regularly test backup restoration procedures'] : ['Test backups quarterly and ensure offline/immutable copies exist'],
  ));

  const levels = controls.map((c) => c.maturityLevel);
  const overallMaturity: EssentialEightMaturity = Math.min(...levels) as EssentialEightMaturity;

  return {
    organisationId: '',
    assessedAt: clock.isoNow(),
    overallMaturity,
    controls,
  };
}

function assessE8Control(
  name: string,
  level: EssentialEightMaturity,
  target: EssentialEightMaturity,
  findings: string[],
  recommendations: string[],
): EssentialEightControl {
  return { name, maturityLevel: level, targetLevel: target, findings, recommendations };
}

function assessIso27001(posture: SecurityPosture): Iso27001Assessment {
  const controls: Iso27001Control[] = ISO_27001_CONTROLS.map((ctrl) => {
    let status: Iso27001Control['status'];
    const findings: string[] = [];
    const recommendations: string[] = [];

    // Assess each control based on security posture
    switch (ctrl.id) {
      case 'A.5.1':
        status = posture.incidentResponsePlan ? 'compliant' : 'partially_compliant';
        if (!posture.incidentResponsePlan) {
          findings.push('Security policy framework incomplete');
          recommendations.push('Develop and approve comprehensive information security policy');
        }
        break;
      case 'A.8.2':
        status = posture.accessControls === 'strong' ? 'compliant' : posture.accessControls === 'moderate' ? 'partially_compliant' : 'non_compliant';
        if (status !== 'compliant') {
          findings.push('Privileged access management needs improvement');
          recommendations.push('Implement privileged access management solution');
        }
        break;
      case 'A.8.5':
        status = posture.mfaEnabled ? 'compliant' : 'non_compliant';
        if (!posture.mfaEnabled) {
          findings.push('Secure authentication not fully implemented');
          recommendations.push('Deploy multi-factor authentication across all systems');
        }
        break;
      case 'A.8.7':
        status = posture.patchManagement === 'strong' ? 'compliant' : 'partially_compliant';
        if (posture.patchManagement !== 'strong') {
          findings.push('Malware protection could be strengthened');
          recommendations.push('Implement endpoint detection and response (EDR)');
        }
        break;
      case 'A.8.8':
        status = posture.vulnerabilityScanningFrequency === 'continuous' ? 'compliant' :
                 posture.vulnerabilityScanningFrequency === 'weekly' ? 'partially_compliant' : 'non_compliant';
        if (status !== 'compliant') {
          findings.push('Vulnerability management frequency insufficient');
          recommendations.push('Implement continuous vulnerability scanning');
        }
        break;
      case 'A.8.15':
        status = posture.loggingAndMonitoring === 'comprehensive' ? 'compliant' :
                 posture.loggingAndMonitoring === 'partial' ? 'partially_compliant' : 'non_compliant';
        if (status !== 'compliant') {
          findings.push('Logging not comprehensive');
          recommendations.push('Implement centralised logging with SIEM integration');
        }
        break;
      case 'A.8.24':
        status = posture.encryptionAtRest && posture.encryptionInTransit ? 'compliant' : 'partially_compliant';
        if (!posture.encryptionAtRest || !posture.encryptionInTransit) {
          findings.push('Encryption gaps identified');
          recommendations.push('Implement encryption at rest and in transit for all sensitive data');
        }
        break;
      case 'A.8.20':
        status = posture.networkSegmentation ? 'compliant' : 'non_compliant';
        if (!posture.networkSegmentation) {
          findings.push('Network security controls insufficient');
          recommendations.push('Implement network segmentation and firewall rules');
        }
        break;
      default:
        // Default assessment based on overall posture strength
        const strongCount = [
          posture.patchManagement === 'strong',
          posture.accessControls === 'strong',
          posture.mfaEnabled,
          posture.encryptionAtRest,
          posture.encryptionInTransit,
          posture.loggingAndMonitoring === 'comprehensive',
        ].filter(Boolean).length;

        status = strongCount >= 4 ? 'compliant' : strongCount >= 2 ? 'partially_compliant' : 'non_compliant';
        if (status !== 'compliant') {
          findings.push(`${ctrl.name} requires attention`);
          recommendations.push(`Review and strengthen ${ctrl.name.toLowerCase()}`);
        }
    }

    return { controlId: ctrl.id, controlName: ctrl.name, annexSection: ctrl.section, status, findings, recommendations };
  });

  const compliant = controls.filter((c) => c.status === 'compliant').length;
  const compliancePercentage = Math.round((compliant / controls.length) * 100);

  return {
    organisationId: '',
    assessedAt: clock.isoNow(),
    compliancePercentage,
    controls,
  };
}

function assessApraCps234(posture: SecurityPosture): ApraCps234Assessment {
  const requirements: ApraCps234Check[] = APRA_CPS234_REQUIREMENTS.map((req) => {
    let status: ApraCps234Check['status'];
    const findings: string[] = [];
    const recommendations: string[] = [];

    switch (req.id) {
      case 'CPS234.1':
        status = posture.securityTraining && posture.incidentResponsePlan ? 'met' : 'partially_met';
        if (status !== 'met') {
          findings.push('Information security capability gaps identified');
          recommendations.push('Ensure adequate information security capability proportionate to threats');
        }
        break;
      case 'CPS234.3':
        status = posture.dataClassification ? 'met' : 'not_met';
        if (!posture.dataClassification) {
          findings.push('Information assets not classified');
          recommendations.push('Classify all information assets by criticality and sensitivity');
        }
        break;
      case 'CPS234.4':
        const controlStrength = [
          posture.accessControls === 'strong',
          posture.mfaEnabled,
          posture.encryptionAtRest,
          posture.networkSegmentation,
        ].filter(Boolean).length;
        status = controlStrength >= 3 ? 'met' : controlStrength >= 1 ? 'partially_met' : 'not_met';
        if (status !== 'met') {
          findings.push('Information security controls not commensurate with threats');
          recommendations.push('Strengthen controls to protect information assets proportionate to threats');
        }
        break;
      case 'CPS234.5':
        status = posture.incidentResponsePlan ? 'met' : 'not_met';
        if (!posture.incidentResponsePlan) {
          findings.push('No incident response plan in place');
          recommendations.push('Develop and regularly test an incident response plan');
        }
        break;
      case 'CPS234.6':
        status = posture.vulnerabilityScanningFrequency === 'continuous' || posture.vulnerabilityScanningFrequency === 'weekly' ? 'met' : 'partially_met';
        if (status !== 'met') {
          findings.push('Control effectiveness testing not sufficiently frequent');
          recommendations.push('Implement regular testing of information security control effectiveness');
        }
        break;
      case 'CPS234.9':
        status = posture.thirdPartyRiskManagement ? 'met' : 'not_met';
        if (!posture.thirdPartyRiskManagement) {
          findings.push('Third-party risk management not established');
          recommendations.push('Implement third-party information security risk management programme');
        }
        break;
      default: {
        const overallStrength = [
          posture.incidentResponsePlan,
          posture.securityTraining,
          posture.dataClassification,
          posture.loggingAndMonitoring === 'comprehensive',
        ].filter(Boolean).length;
        status = overallStrength >= 3 ? 'met' : overallStrength >= 1 ? 'partially_met' : 'not_met';
        if (status !== 'met') {
          findings.push(`${req.name} requires attention`);
          recommendations.push(`Address ${req.name.toLowerCase()} requirements`);
        }
      }
    }

    return { requirementId: req.id, requirementName: req.name, category: req.category, status, findings, recommendations };
  });

  const met = requirements.filter((r) => r.status === 'met').length;
  const total = requirements.length;
  const overallStatus = met === total ? 'compliant' : met >= total / 2 ? 'partially_compliant' : 'non_compliant';

  return {
    organisationId: '',
    assessedAt: clock.isoNow(),
    overallStatus,
    requirements,
  };
}

function assessNdbReadiness(posture: SecurityPosture): NdbReadinessAssessment {
  const checks: NdbReadinessCheck[] = NDB_AREAS.map((area) => {
    let status: NdbReadinessCheck['status'] = 'not_ready';
    const findings: string[] = [];
    const recommendations: string[] = [];

    switch (area) {
      case 'Data breach response plan':
        status = posture.incidentResponsePlan ? 'ready' : 'not_ready';
        if (!posture.incidentResponsePlan) {
          findings.push('No data breach response plan exists');
          recommendations.push('Develop a data breach response plan aligned to the NDB scheme');
        }
        break;
      case 'Breach detection capability':
        status = posture.loggingAndMonitoring === 'comprehensive' ? 'ready' :
                 posture.loggingAndMonitoring === 'partial' ? 'partially_ready' : 'not_ready';
        if (status !== 'ready') {
          findings.push('Breach detection capabilities insufficient');
          recommendations.push('Implement comprehensive monitoring and alerting');
        }
        break;
      case 'Assessment process for eligible data breaches':
        status = posture.incidentResponsePlan && posture.dataClassification ? 'ready' : 'partially_ready';
        if (status !== 'ready') {
          findings.push('Assessment process for eligible data breaches needs formalisation');
          recommendations.push('Establish formal assessment criteria for determining eligible breaches');
        }
        break;
      case 'Notification procedures (to OAIC)':
        status = posture.incidentResponsePlan ? 'partially_ready' : 'not_ready';
        findings.push('OAIC notification procedures not fully documented');
        recommendations.push('Document OAIC notification procedures with templates and timeframes');
        break;
      case 'Notification procedures (to affected individuals)':
        status = posture.incidentResponsePlan ? 'partially_ready' : 'not_ready';
        findings.push('Individual notification procedures not fully documented');
        recommendations.push('Prepare notification templates and processes for affected individuals');
        break;
      case 'Record-keeping of data breaches':
        status = posture.loggingAndMonitoring === 'comprehensive' ? 'ready' : 'partially_ready';
        if (status !== 'ready') {
          findings.push('Data breach record-keeping not comprehensive');
          recommendations.push('Implement a breach register to track all breaches regardless of severity');
        }
        break;
    }

    return { area, status, findings, recommendations };
  });

  const ready = checks.filter((c) => c.status === 'ready').length;
  const total = checks.length;
  const overallReadiness = ready === total ? 'ready' : ready >= total / 2 ? 'partially_ready' : 'not_ready';

  return {
    organisationId: '',
    assessedAt: clock.isoNow(),
    overallReadiness,
    checks,
  };
}

export function runFullAssessment(
  organisationId: string,
  posture: SecurityPosture,
  frameworkIds?: string[],
): ComplianceAssessment {
  const allFrameworks = frameworkIds ?? ['essential-eight', 'iso-27001', 'apra-cps-234', 'ndb'];

  const assessment: ComplianceAssessment = {
    organisationId,
    assessedAt: clock.isoNow(),
    frameworks: {},
    overallScore: 0,
    summary: '',
  };

  const scores: number[] = [];

  if (allFrameworks.includes('essential-eight')) {
    const e8 = assessEssentialEight(posture);
    e8.organisationId = organisationId;
    assessment.frameworks.essentialEight = e8;
    scores.push((e8.overallMaturity / 3) * 100);
  }

  if (allFrameworks.includes('iso-27001')) {
    const iso = assessIso27001(posture);
    iso.organisationId = organisationId;
    assessment.frameworks.iso27001 = iso;
    scores.push(iso.compliancePercentage);
  }

  if (allFrameworks.includes('apra-cps-234')) {
    const apra = assessApraCps234(posture);
    apra.organisationId = organisationId;
    assessment.frameworks.apraCps234 = apra;
    const met = apra.requirements.filter((r) => r.status === 'met').length;
    scores.push(Math.round((met / apra.requirements.length) * 100));
  }

  if (allFrameworks.includes('ndb')) {
    const ndb = assessNdbReadiness(posture);
    ndb.organisationId = organisationId;
    assessment.frameworks.ndbReadiness = ndb;
    const ready = ndb.checks.filter((c) => c.status === 'ready').length;
    scores.push(Math.round((ready / ndb.checks.length) * 100));
  }

  assessment.overallScore = scores.length > 0
    ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length)
    : 0;

  assessment.summary = `Compliance assessment for organisation ${organisationId}: ` +
    `Overall score ${assessment.overallScore}% across ${scores.length} framework(s). ` +
    (assessment.overallScore >= 80 ? 'Good compliance posture — continue monitoring.' :
     assessment.overallScore >= 50 ? 'Moderate compliance — several gaps require attention.' :
     'Significant compliance gaps identified — immediate remediation recommended.');

  return assessment;
}

export function getEssentialEightStatus(
  organisationId: string,
  posture: SecurityPosture,
): EssentialEightAssessment {
  const e8 = assessEssentialEight(posture);
  e8.organisationId = organisationId;
  return e8;
}

export function getGapAnalysis(
  organisationId: string,
  posture: SecurityPosture,
): GapAnalysis {
  const assessment = runFullAssessment(organisationId, posture);
  const gaps: ComplianceGap[] = [];

  // Essential Eight gaps
  if (assessment.frameworks.essentialEight) {
    for (const ctrl of assessment.frameworks.essentialEight.controls) {
      if (ctrl.maturityLevel < ctrl.targetLevel) {
        gaps.push({
          framework: 'Essential Eight',
          controlId: ctrl.name,
          controlName: ctrl.name,
          currentState: `Maturity Level ${ctrl.maturityLevel}`,
          requiredState: `Maturity Level ${ctrl.targetLevel}`,
          priority: ctrl.maturityLevel === 0 ? 'critical' : ctrl.maturityLevel === 1 ? 'high' : 'medium',
          remediation: ctrl.recommendations[0] ?? 'Address control gap',
          estimatedEffort: ctrl.maturityLevel === 0 ? '4-8 weeks' : ctrl.maturityLevel === 1 ? '2-4 weeks' : '1-2 weeks',
        });
      }
    }
  }

  // ISO 27001 gaps
  if (assessment.frameworks.iso27001) {
    for (const ctrl of assessment.frameworks.iso27001.controls) {
      if (ctrl.status !== 'compliant' && ctrl.status !== 'not_applicable') {
        gaps.push({
          framework: 'ISO 27001',
          controlId: ctrl.controlId,
          controlName: ctrl.controlName,
          currentState: ctrl.status.replace('_', ' '),
          requiredState: 'compliant',
          priority: ctrl.status === 'non_compliant' ? 'high' : 'medium',
          remediation: ctrl.recommendations[0] ?? 'Address control gap',
          estimatedEffort: ctrl.status === 'non_compliant' ? '4-6 weeks' : '2-3 weeks',
        });
      }
    }
  }

  // APRA CPS 234 gaps
  if (assessment.frameworks.apraCps234) {
    for (const req of assessment.frameworks.apraCps234.requirements) {
      if (req.status !== 'met' && req.status !== 'not_applicable') {
        gaps.push({
          framework: 'APRA CPS 234',
          controlId: req.requirementId,
          controlName: req.requirementName,
          currentState: req.status.replace('_', ' '),
          requiredState: 'met',
          priority: req.status === 'not_met' ? 'critical' : 'high',
          remediation: req.recommendations[0] ?? 'Address requirement gap',
          estimatedEffort: req.status === 'not_met' ? '6-8 weeks' : '3-4 weeks',
        });
      }
    }
  }

  // NDB gaps
  if (assessment.frameworks.ndbReadiness) {
    for (const check of assessment.frameworks.ndbReadiness.checks) {
      if (check.status !== 'ready') {
        gaps.push({
          framework: 'Privacy Act NDB',
          controlId: check.area,
          controlName: check.area,
          currentState: check.status.replace('_', ' '),
          requiredState: 'ready',
          priority: check.status === 'not_ready' ? 'high' : 'medium',
          remediation: check.recommendations[0] ?? 'Address readiness gap',
          estimatedEffort: check.status === 'not_ready' ? '3-4 weeks' : '1-2 weeks',
        });
      }
    }
  }

  // Sort by priority
  const priorityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  gaps.sort((a, b) => (priorityOrder[a.priority] ?? 99) - (priorityOrder[b.priority] ?? 99));

  return {
    organisationId,
    analysedAt: clock.isoNow(),
    totalGaps: gaps.length,
    criticalGaps: gaps.filter((g) => g.priority === 'critical').length,
    gaps,
  };
}

export function generateComplianceReport(
  organisationId: string,
  posture: SecurityPosture,
): ComplianceReport {
  const assessment = runFullAssessment(organisationId, posture);
  const gapAnalysis = getGapAnalysis(organisationId, posture);

  const allRecommendations: string[] = [];

  // Gather all recommendations from gaps
  for (const gap of gapAnalysis.gaps.filter((g) => g.priority === 'critical' || g.priority === 'high')) {
    allRecommendations.push(`[${gap.framework}] ${gap.remediation}`);
  }

  const executiveSummary =
    `This report presents the compliance assessment for organisation ${organisationId}. ` +
    `The overall compliance score is ${assessment.overallScore}%. ` +
    `${gapAnalysis.totalGaps} compliance gap(s) were identified, ` +
    `of which ${gapAnalysis.criticalGaps} are critical. ` +
    (gapAnalysis.criticalGaps > 0
      ? 'Immediate attention is required to address critical gaps.'
      : 'No critical gaps found, but continued improvement is recommended.');

  return {
    organisationId,
    generatedAt: clock.isoNow(),
    title: `Compliance Assessment Report — ${organisationId}`,
    executiveSummary,
    assessment,
    gapAnalysis,
    recommendations: allRecommendations.slice(0, 10),
    reportFormat: 'json',
  };
}

export function listFrameworks(): ComplianceFramework[] {
  return [...FRAMEWORKS];
}
