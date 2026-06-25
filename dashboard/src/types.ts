export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type SecurityTier = 1 | 2 | 3;
export type RotationStatus = 'ok' | 'due' | 'overdue' | 'unknown';

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
  tier: SecurityTier;
  businessImpact: string;
  quickChecks: number;
  deepChecks: number;
  findings: string[];
  recommendations: string[];
  evidence: Evidence[];
  estimatedApiCalls: number;
}

export interface SecretFinding {
  id: string;
  repository: string;
  workflowPath: string;
  secretType: string;
  severity: string;
  location: string;
  masked: string;
  confirmed: boolean;
  remediation: string;
}

export interface NetworkFinding {
  id: string;
  repository: string;
  workflowPath: string;
  endpoint: string;
  protocol: string;
  viaZscaler: boolean;
  companyOwned: boolean;
  action: string;
  severity: string;
  blocked: boolean;
}

export interface SecretRotationEntry {
  secretName: string;
  repository: string;
  lastRotatedDays: number;
  status: RotationStatus;
  nextRotationDays: number;
  autoRotateEnabled: boolean;
}

export interface HardeningSummary {
  thirdPartyBlocked: number;
  thirdPartyAllowed: number;
  thirdPartyTotal: number;
  secretLeaksFound: number;
  maliciousPatterns: number;
  networkViolations: number;
  secretsOverdue: number;
  secretsDue: number;
  secretsOk: number;
  tier1Count: number;
  tier2Count: number;
  tier3Count: number;
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
  secretFindings?: SecretFinding[];
  networkFindings?: NetworkFinding[];
  rotationStatus?: SecretRotationEntry[];
  hardeningSummary?: HardeningSummary;
}
