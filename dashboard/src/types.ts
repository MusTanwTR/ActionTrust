export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface Evidence {
  type: string;
  key: string;
  value: string;
  source: string;
  confidence: number;
}

export interface RankedRisk {
  entityId: string;
  entityType: string;
  score: number;
  level: RiskLevel | string;
  businessImpact: string;
  quickChecks: number;
  deepChecks: number;
  findings: string[];
  recommendations: string[];
  evidence: Evidence[];
  estimatedApiCalls: number;
}

export interface DatasetAssessmentReport {
  generatedAt: string;
  datasetPath: string;
  riskModel: {
    formula: string;
  };
  summary: {
    totalActionUses: number;
    distinctActions: number;
    reposUsingActions: number;
    workflowFilesWithActions: number;
    highOrCriticalActions: number;
    highOrCriticalRepos: number;
    estimatedApiCalls: number;
    estimatedLlmTokens: number;
    estimatedRuntimeMs: number;
    estimatedAnalystMinutes: number;
  };
  topRiskyActions: RankedRisk[];
  topSafeActions: RankedRisk[];
  topRiskyWorkflows?: RankedRisk[];
  topRiskyRepositories: RankedRisk[];
  topRiskyBusinessUnits: RankedRisk[];
  topRiskySoftwareClasses?: RankedRisk[];
  prioritizedRecommendations: string[];
  operationalProcess: Array<{
    decision: string;
    criteria: string[];
    nextSteps: string[];
    reassessment: string;
  }>;
  costAndScalabilityNotes: string[];
}
