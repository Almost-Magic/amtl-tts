/**
 * Milestone 19: Threat Actor Profiler — Service
 *
 * Maps vulnerabilities to MITRE ATT&CK, identifies likely threat actors,
 * constructs kill chain analyses, and generates executive briefings.
 */
import { generateId } from '../utils/id.js';
import { clock } from '../utils/clock.js';
import type { Vulnerability } from '../models/shared.js';
import type {
  MitreMapping,
  ThreatActor,
  KillChainPhase,
  KillChainAnalysis,
  ThreatActorProfile,
  ExecutiveBriefing,
} from '../models/threat-actor.js';

// MITRE ATT&CK technique database (subset)
const MITRE_TECHNIQUES: Record<string, { id: string; name: string; tacticId: string; tacticName: string }> = {
  'sql_injection':      { id: 'T1190', name: 'Exploit Public-Facing Application', tacticId: 'TA0001', tacticName: 'Initial Access' },
  'xss':               { id: 'T1189', name: 'Drive-by Compromise', tacticId: 'TA0001', tacticName: 'Initial Access' },
  'rce':               { id: 'T1203', name: 'Exploitation for Client Execution', tacticId: 'TA0002', tacticName: 'Execution' },
  'auth_bypass':       { id: 'T1078', name: 'Valid Accounts', tacticId: 'TA0001', tacticName: 'Initial Access' },
  'privilege_escalation': { id: 'T1068', name: 'Exploitation for Privilege Escalation', tacticId: 'TA0004', tacticName: 'Privilege Escalation' },
  'missing_header':    { id: 'T1189', name: 'Drive-by Compromise', tacticId: 'TA0001', tacticName: 'Initial Access' },
  'weak_crypto':       { id: 'T1557', name: 'Adversary-in-the-Middle', tacticId: 'TA0006', tacticName: 'Credential Access' },
  'ssrf':              { id: 'T1190', name: 'Exploit Public-Facing Application', tacticId: 'TA0001', tacticName: 'Initial Access' },
  'path_traversal':    { id: 'T1083', name: 'File and Directory Discovery', tacticId: 'TA0007', tacticName: 'Discovery' },
  'insecure_deserialization': { id: 'T1059', name: 'Command and Scripting Interpreter', tacticId: 'TA0002', tacticName: 'Execution' },
  'default_credentials': { id: 'T1078.001', name: 'Default Accounts', tacticId: 'TA0001', tacticName: 'Initial Access' },
  'open_redirect':     { id: 'T1566.002', name: 'Spearphishing Link', tacticId: 'TA0001', tacticName: 'Initial Access' },
  'dns_misconfiguration': { id: 'T1584.002', name: 'DNS Server', tacticId: 'TA0042', tacticName: 'Resource Development' },
  'exposed_admin':     { id: 'T1133', name: 'External Remote Services', tacticId: 'TA0001', tacticName: 'Initial Access' },
  'data_exposure':     { id: 'T1530', name: 'Data from Cloud Storage', tacticId: 'TA0009', tacticName: 'Collection' },
};

// Known threat actor database
const THREAT_ACTORS: ThreatActor[] = [
  {
    id: 'ta-001', name: 'APT28 (Fancy Bear)', aliases: ['Fancy Bear', 'Sofacy', 'Strontium'],
    origin: 'Russia', motivation: 'espionage', sophistication: 'advanced',
    targetIndustries: ['government', 'defence', 'technology', 'energy'],
    targetGeographies: ['Australia', 'United States', 'Europe', 'NATO'],
    knownTechniques: ['T1190', 'T1078', 'T1203', 'T1068', 'T1557'],
    relevanceScore: 0, description: 'State-sponsored group linked to Russian military intelligence (GRU)',
  },
  {
    id: 'ta-002', name: 'APT41 (Wicked Panda)', aliases: ['Wicked Panda', 'Barium', 'Winnti'],
    origin: 'China', motivation: 'espionage', sophistication: 'advanced',
    targetIndustries: ['technology', 'healthcare', 'finance', 'telecommunications'],
    targetGeographies: ['Australia', 'United States', 'Asia Pacific'],
    knownTechniques: ['T1190', 'T1059', 'T1078', 'T1068'],
    relevanceScore: 0, description: 'Dual espionage and financially-motivated group linked to Chinese state interests',
  },
  {
    id: 'ta-003', name: 'FIN7', aliases: ['Carbanak', 'Navigator'],
    origin: 'Eastern Europe', motivation: 'financial', sophistication: 'high',
    targetIndustries: ['retail', 'hospitality', 'finance', 'healthcare'],
    targetGeographies: ['United States', 'Europe', 'Australia'],
    knownTechniques: ['T1190', 'T1189', 'T1566.002', 'T1078'],
    relevanceScore: 0, description: 'Financially motivated group targeting payment systems and financial data',
  },
  {
    id: 'ta-004', name: 'Lazarus Group', aliases: ['Hidden Cobra', 'Zinc'],
    origin: 'North Korea', motivation: 'financial', sophistication: 'advanced',
    targetIndustries: ['finance', 'cryptocurrency', 'technology', 'defence'],
    targetGeographies: ['Global', 'Australia', 'Asia Pacific'],
    knownTechniques: ['T1190', 'T1203', 'T1059', 'T1078.001'],
    relevanceScore: 0, description: 'State-sponsored group conducting financial theft and espionage operations',
  },
  {
    id: 'ta-005', name: 'LockBit Syndicate', aliases: ['LockBit 3.0'],
    origin: 'International', motivation: 'financial', sophistication: 'medium',
    targetIndustries: ['healthcare', 'education', 'government', 'finance', 'technology'],
    targetGeographies: ['Global', 'Australia', 'United States', 'Europe'],
    knownTechniques: ['T1190', 'T1078', 'T1133', 'T1068'],
    relevanceScore: 0, description: 'Ransomware-as-a-Service operation with extensive affiliate network',
  },
  {
    id: 'ta-006', name: 'Anonymous Sudan', aliases: ['Storm-1359'],
    origin: 'Unknown', motivation: 'hacktivism', sophistication: 'low',
    targetIndustries: ['government', 'technology', 'healthcare'],
    targetGeographies: ['Australia', 'Europe', 'United States'],
    knownTechniques: ['T1189', 'T1190'],
    relevanceScore: 0, description: 'Hacktivist group conducting DDoS attacks and data exfiltration',
  },
];

// Kill chain phases (Lockheed Martin Cyber Kill Chain)
const KILL_CHAIN_PHASES = [
  { phase: 'Reconnaissance', order: 1, description: 'Adversary identifies and selects targets' },
  { phase: 'Weaponisation', order: 2, description: 'Adversary creates deliverable payload' },
  { phase: 'Delivery', order: 3, description: 'Adversary transmits weapon to target environment' },
  { phase: 'Exploitation', order: 4, description: 'Adversary exploits vulnerability to gain access' },
  { phase: 'Installation', order: 5, description: 'Adversary installs persistent backdoor' },
  { phase: 'Command & Control', order: 6, description: 'Adversary establishes remote control channel' },
  { phase: 'Actions on Objectives', order: 7, description: 'Adversary achieves intended goal' },
];

// Map finding types to MITRE techniques
function mapToMitre(vulnerabilities: Vulnerability[]): MitreMapping[] {
  const mappings: MitreMapping[] = [];

  for (const vuln of vulnerabilities) {
    // Check direct finding type mapping
    const technique = MITRE_TECHNIQUES[vuln.findingType];
    if (technique) {
      mappings.push({
        vulnerabilityId: vuln.id,
        techniqueId: technique.id,
        techniqueName: technique.name,
        tacticId: technique.tacticId,
        tacticName: technique.tacticName,
      });
    }

    // Also check MITRE techniques embedded in the vulnerability
    if (vuln.mitreTechniques) {
      for (const techId of vuln.mitreTechniques) {
        const matchedTech = Object.values(MITRE_TECHNIQUES).find((t) => t.id === techId);
        if (matchedTech && !mappings.some((m) => m.vulnerabilityId === vuln.id && m.techniqueId === techId)) {
          mappings.push({
            vulnerabilityId: vuln.id,
            techniqueId: matchedTech.id,
            techniqueName: matchedTech.name,
            tacticId: matchedTech.tacticId,
            tacticName: matchedTech.tacticName,
          });
        }
      }
    }
  }

  return mappings;
}

/** Calculate threat actor relevance score (0-100) */
function scoreActorRelevance(
  actor: ThreatActor,
  mappedTechniques: string[],
  industry: string,
  geography: string,
): number {
  let score = 0;

  // Technique overlap (up to 40 points)
  const techniqueOverlap = actor.knownTechniques.filter((t) => mappedTechniques.includes(t)).length;
  const techniqueScore = actor.knownTechniques.length > 0
    ? (techniqueOverlap / actor.knownTechniques.length) * 40
    : 0;
  score += techniqueScore;

  // Industry targeting (up to 30 points)
  if (actor.targetIndustries.some((i) => i.toLowerCase() === industry.toLowerCase())) {
    score += 30;
  }

  // Geographic targeting (up to 20 points)
  if (actor.targetGeographies.some((g) =>
    g.toLowerCase() === geography.toLowerCase() || g.toLowerCase() === 'global',
  )) {
    score += 20;
  }

  // Sophistication bonus (up to 10 points)
  const sophScores: Record<string, number> = { advanced: 10, high: 7, medium: 4, low: 2 };
  score += sophScores[actor.sophistication] ?? 0;

  return Math.min(100, Math.round(score));
}

/** Build kill chain analysis from mapped techniques and vulnerabilities */
function buildKillChain(
  organisationId: string,
  mappings: MitreMapping[],
  vulnerabilities: Vulnerability[],
): KillChainAnalysis {
  const mappedTactics = new Set(mappings.map((m) => m.tacticName));
  const mappedTechniques = mappings.map((m) => m.techniqueId);

  // Map tactics to kill chain phases
  const tacticToPhaseMap: Record<string, string> = {
    'Initial Access': 'Delivery',
    'Execution': 'Exploitation',
    'Privilege Escalation': 'Exploitation',
    'Credential Access': 'Exploitation',
    'Discovery': 'Reconnaissance',
    'Collection': 'Actions on Objectives',
    'Resource Development': 'Weaponisation',
  };

  const exposedPhases = new Set<string>();
  for (const tactic of mappedTactics) {
    const phase = tacticToPhaseMap[tactic];
    if (phase) exposedPhases.add(phase);
  }

  const phases: KillChainPhase[] = KILL_CHAIN_PHASES.map((kc) => {
    const isExposed = exposedPhases.has(kc.phase);
    const relevantTechniques = mappedTechniques.filter((t) => {
      const tech = Object.values(MITRE_TECHNIQUES).find((mt) => mt.id === t);
      return tech && tacticToPhaseMap[tech.tacticName] === kc.phase;
    });

    let exposure: 'exposed' | 'partially_mitigated' | 'mitigated';
    let riskLevel: 'critical' | 'high' | 'medium' | 'low';

    if (isExposed && relevantTechniques.length > 1) {
      exposure = 'exposed';
      riskLevel = 'critical';
    } else if (isExposed) {
      exposure = 'partially_mitigated';
      riskLevel = 'high';
    } else {
      exposure = 'mitigated';
      riskLevel = 'low';
    }

    return {
      phase: kc.phase,
      order: kc.order,
      description: kc.description,
      viableTechniques: relevantTechniques,
      currentExposure: exposure,
      riskLevel,
    };
  });

  // Count complete attack paths (phases where attack can progress through)
  let completePaths = 0;
  const exposedPhaseOrders = phases.filter((p) => p.currentExposure !== 'mitigated').map((p) => p.order);
  // A complete path needs at least delivery + exploitation + actions
  if (exposedPhaseOrders.includes(3) && exposedPhaseOrders.includes(4) && exposedPhaseOrders.includes(7)) {
    completePaths = 1;
  }
  if (exposedPhaseOrders.length >= 5) completePaths = 2;
  if (exposedPhaseOrders.length >= 6) completePaths = 3;

  const mostLikelyPath = phases
    .filter((p) => p.currentExposure !== 'mitigated')
    .sort((a, b) => a.order - b.order)
    .map((p) => p.phase);

  const criticalPhases = phases.filter((p) => p.riskLevel === 'critical').length;
  const overallRisk: KillChainAnalysis['overallRisk'] =
    criticalPhases >= 3 ? 'critical' :
    criticalPhases >= 2 ? 'high' :
    criticalPhases >= 1 ? 'medium' : 'low';

  return {
    organisationId,
    analysedAt: clock.isoNow(),
    phases,
    completePaths,
    mostLikelyPath,
    overallRisk,
  };
}

/** Generate executive briefing */
function generateBriefing(
  organisationId: string,
  actors: ThreatActor[],
  killChain: KillChainAnalysis,
): ExecutiveBriefing {
  const topActors = actors.filter((a) => a.relevanceScore >= 30).slice(0, 5);

  const topThreats = topActors.map((a) => ({
    actorName: a.name,
    relevanceScore: a.relevanceScore,
    primaryMotivation: a.motivation,
    likelihood: a.relevanceScore >= 70 ? 'High' : a.relevanceScore >= 50 ? 'Medium' : 'Low',
  }));

  const recommendations: string[] = [];
  const exposedPhases = killChain.phases.filter((p) => p.currentExposure === 'exposed');

  if (exposedPhases.length > 0) {
    recommendations.push(
      `Address ${exposedPhases.length} exposed kill chain phase(s): ${exposedPhases.map((p) => p.phase).join(', ')}`,
    );
  }

  if (topActors.some((a) => a.motivation === 'financial')) {
    recommendations.push('Strengthen financial data controls — financially-motivated actors identified');
  }
  if (topActors.some((a) => a.motivation === 'espionage')) {
    recommendations.push('Review data classification and access controls — state-sponsored espionage threat detected');
  }
  if (killChain.completePaths > 0) {
    recommendations.push(`Remediate ${killChain.completePaths} viable attack path(s) through the kill chain`);
  }
  recommendations.push('Implement continuous threat monitoring aligned to identified actor TTPs');

  const summary = topActors.length > 0
    ? `${topActors.length} threat actor group(s) have been identified as relevant to your organisation. ` +
      `The highest-relevance actor is ${topActors[0].name} (score: ${topActors[0].relevanceScore}/100), ` +
      `motivated by ${topActors[0].motivation}. ` +
      `Kill chain analysis shows ${killChain.completePaths} complete attack path(s) with overall risk rated ${killChain.overallRisk}.`
    : 'No highly relevant threat actors identified at this time. Continue routine monitoring.';

  return {
    organisationId,
    generatedAt: clock.isoNow(),
    summary,
    topThreats,
    recommendations,
  };
}

export function profileOrganisation(
  organisationId: string,
  vulnerabilities: Vulnerability[],
  industry: string,
  geography: string,
): ThreatActorProfile {
  // Step 1: Map vulnerabilities to MITRE ATT&CK
  const mitreMappings = mapToMitre(vulnerabilities);
  const mappedTechniqueIds = [...new Set(mitreMappings.map((m) => m.techniqueId))];

  // Step 2: Score and identify threat actors
  const scoredActors = THREAT_ACTORS.map((actor) => ({
    ...actor,
    id: generateId(),
    relevanceScore: scoreActorRelevance(actor, mappedTechniqueIds, industry, geography),
  })).sort((a, b) => b.relevanceScore - a.relevanceScore);

  // Step 3: Build kill chain
  const killChain = buildKillChain(organisationId, mitreMappings, vulnerabilities);

  // Step 4: Generate briefing
  const briefing = generateBriefing(organisationId, scoredActors, killChain);

  return {
    organisationId,
    generatedAt: clock.isoNow(),
    mitreMappings,
    identifiedActors: scoredActors,
    killChain,
    executiveBriefing: briefing.summary,
  };
}

export function getMitreMapping(
  vulnerabilities: Vulnerability[],
): MitreMapping[] {
  return mapToMitre(vulnerabilities);
}

export function getKillChainAnalysis(
  organisationId: string,
  vulnerabilities: Vulnerability[],
): KillChainAnalysis {
  const mappings = mapToMitre(vulnerabilities);
  return buildKillChain(organisationId, mappings, vulnerabilities);
}

export function getExecutiveBriefing(
  organisationId: string,
  vulnerabilities: Vulnerability[],
  industry: string,
  geography: string,
): ExecutiveBriefing {
  const mappings = mapToMitre(vulnerabilities);
  const mappedTechniqueIds = [...new Set(mappings.map((m) => m.techniqueId))];
  const scoredActors = THREAT_ACTORS.map((actor) => ({
    ...actor,
    id: generateId(),
    relevanceScore: scoreActorRelevance(actor, mappedTechniqueIds, industry, geography),
  })).sort((a, b) => b.relevanceScore - a.relevanceScore);

  const killChain = buildKillChain(organisationId, mappings, vulnerabilities);
  return generateBriefing(organisationId, scoredActors, killChain);
}
