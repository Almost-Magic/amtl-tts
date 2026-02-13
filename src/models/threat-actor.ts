/**
 * Milestone 19: Threat Actor Profiler — Types
 */

export interface MitreMapping {
  vulnerabilityId: string;
  techniqueId: string;
  techniqueName: string;
  tacticId: string;
  tacticName: string;
}

export interface ThreatActor {
  id: string;
  name: string;
  aliases: string[];
  origin: string;
  motivation: 'financial' | 'espionage' | 'hacktivism' | 'destruction' | 'unknown';
  sophistication: 'low' | 'medium' | 'high' | 'advanced';
  targetIndustries: string[];
  targetGeographies: string[];
  knownTechniques: string[];
  relevanceScore: number; // 0-100
  description: string;
}

export interface KillChainPhase {
  phase: string;
  order: number;
  description: string;
  viableTechniques: string[];
  currentExposure: 'exposed' | 'partially_mitigated' | 'mitigated';
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
}

export interface KillChainAnalysis {
  organisationId: string;
  analysedAt: string;
  phases: KillChainPhase[];
  completePaths: number;
  mostLikelyPath: string[];
  overallRisk: 'critical' | 'high' | 'medium' | 'low';
}

export interface ThreatActorProfile {
  organisationId: string;
  generatedAt: string;
  mitreMappings: MitreMapping[];
  identifiedActors: ThreatActor[];
  killChain: KillChainAnalysis;
  executiveBriefing: string;
}

export interface ExecutiveBriefing {
  organisationId: string;
  generatedAt: string;
  summary: string;
  topThreats: Array<{
    actorName: string;
    relevanceScore: number;
    primaryMotivation: string;
    likelihood: string;
  }>;
  recommendations: string[];
}
