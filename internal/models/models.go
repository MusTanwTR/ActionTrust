package models

import "time"

type PinningStrategy string

const (
	PinSHA     PinningStrategy = "sha"
	PinTag     PinningStrategy = "tag"
	PinBranch  PinningStrategy = "branch"
	PinMutable PinningStrategy = "mutable"
	PinUnknown PinningStrategy = "unknown"
)

type AssessmentOptions struct {
	DeepAnalysis bool `json:"deepAnalysis"`
}

type ActionMetadata struct {
	Stars               int   `json:"stars"`
	Contributors        int   `json:"contributors"`
	Archived            bool  `json:"archived"`
	RecentlyRenamed     bool  `json:"recentlyRenamed"`
	RecentlyTransferred bool  `json:"recentlyTransferred"`
	SuspiciousRelease   bool  `json:"suspiciousRelease"`
	LastReleaseDays     int   `json:"lastReleaseDays"`
	KnownAdvisories     int   `json:"knownAdvisories"`
	HasSecurityPolicy   *bool `json:"hasSecurityPolicy"`

	// 0-100 scale where higher means better reputation.
	MaintainerReputation *int `json:"maintainerReputation"`
	// 0-100 scale where higher means higher dependency risk.
	DependencyRisk *int `json:"dependencyRisk"`
}

type ActionUsage struct {
	ID              string          `json:"id"`
	VersionRef      string          `json:"versionRef"`
	RepoURL         string          `json:"repoURL"`
	UsageCount      int             `json:"usageCount"`
	PinningStrategy PinningStrategy `json:"pinningStrategy"`
	IsFirstParty    bool            `json:"isFirstParty"`
	Allowlisted     bool            `json:"allowlisted"`
	Denylisted      bool            `json:"denylisted"`
	Metadata        ActionMetadata  `json:"metadata"`
}

type WorkflowActionRef struct {
	Identifier      string          `json:"identifier"`
	VersionRef      string          `json:"versionRef"`
	PinningStrategy PinningStrategy `json:"pinningStrategy"`
	IsThirdParty    bool            `json:"isThirdParty"`
}

type WorkflowUsage struct {
	ID                     string              `json:"id"`
	Repository             string              `json:"repository"`
	WorkflowPath           string              `json:"workflowPath"`
	Triggers               []string            `json:"triggers"`
	TokenPermissions       map[string]string   `json:"tokenPermissions"`
	Actions                []WorkflowActionRef `json:"actions"`
	UsesThirdPartyActions  bool                `json:"usesThirdPartyActions"`
	SecretsExposed         bool                `json:"secretsExposed"`
	SelfHostedRunner       bool                `json:"selfHostedRunner"`
	UntrustedPR            bool                `json:"untrustedPR"`
	UntrustedInputInScript bool                `json:"untrustedInputInScript"`
	ArtifactFromUntrusted  bool                `json:"artifactFromUntrusted"`
	DeploymentJob          bool                `json:"deploymentJob"`
	EnvironmentProtected   bool                `json:"environmentProtected"`
}

type AssessmentRequest struct {
	Actions   []ActionUsage     `json:"actions"`
	Workflows []WorkflowUsage   `json:"workflows"`
	Options   AssessmentOptions `json:"options"`
}

type ActionAssessmentRequest struct {
	Actions []ActionUsage     `json:"actions"`
	Options AssessmentOptions `json:"options"`
}

type WorkflowAssessmentRequest struct {
	Workflows []WorkflowUsage   `json:"workflows"`
	Options   AssessmentOptions `json:"options"`
}

type Evidence struct {
	Type       string  `json:"type"`
	Key        string  `json:"key"`
	Value      string  `json:"value"`
	Source     string  `json:"source"`
	Confidence float64 `json:"confidence"`
}

type RiskFinding struct {
	ID             string     `json:"id"`
	Scope          string     `json:"scope"`
	Title          string     `json:"title"`
	Description    string     `json:"description"`
	Severity       string     `json:"severity"`
	Score          int        `json:"score"`
	Confirmed      bool       `json:"confirmed"`
	Recommendation string     `json:"recommendation"`
	Evidence       []Evidence `json:"evidence"`
}

type CostEstimate struct {
	APICallsEstimated   int `json:"apiCallsEstimated"`
	LLMTokensEstimated  int `json:"llmTokensEstimated"`
	RuntimeMsEstimated  int `json:"runtimeMsEstimated"`
	AnalystMinutesSaved int `json:"analystMinutesSaved"`
}

type AssessmentResult struct {
	EntityID        string        `json:"entityId"`
	EntityType      string        `json:"entityType"`
	Score           int           `json:"score"`
	Level           string        `json:"level"`
	QuickChecks     int           `json:"quickChecks"`
	DeepChecks      int           `json:"deepChecks"`
	Findings        []RiskFinding `json:"findings"`
	Recommendations []string      `json:"recommendations"`
	Cost            CostEstimate  `json:"cost"`
}

type AssessmentSummary struct {
	TotalActions          int `json:"totalActions"`
	TotalWorkflows        int `json:"totalWorkflows"`
	LowRisk               int `json:"lowRisk"`
	MediumRisk            int `json:"mediumRisk"`
	HighRisk              int `json:"highRisk"`
	CriticalRisk          int `json:"criticalRisk"`
	TotalFindings         int `json:"totalFindings"`
	EstimatedAPICalls     int `json:"estimatedApiCalls"`
	EstimatedLLMTokens    int `json:"estimatedLlmTokens"`
	EstimatedRuntimeMs    int `json:"estimatedRuntimeMs"`
	EstimatedAnalystSaved int `json:"estimatedAnalystMinutesSaved"`
}

type AssessmentResponse struct {
	GeneratedAt     time.Time          `json:"generatedAt"`
	ActionResults   []AssessmentResult `json:"actionResults"`
	WorkflowResults []AssessmentResult `json:"workflowResults"`
	Summary         AssessmentSummary  `json:"summary"`
	Assumptions     []string           `json:"assumptions"`
	Limitations     []string           `json:"limitations"`
}

type DatasetAssessmentRequest struct {
	BasePath string `json:"basePath"`
	Options  struct {
		DeepAnalysis bool `json:"deepAnalysis"`
		TopN         int  `json:"topN"`
	} `json:"options"`
}

type CheckDefinition struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Weight      int    `json:"weight"`
	Type        string `json:"type"`
}

type RiskModelDefinition struct {
	Formula        string            `json:"formula"`
	QuickChecks    []CheckDefinition `json:"quickChecks"`
	DeepChecks     []CheckDefinition `json:"deepChecks"`
	BusinessImpact []CheckDefinition `json:"businessImpact"`
	Assumptions    []string          `json:"assumptions"`
	Limitations    []string          `json:"limitations"`
}

type RankedRisk struct {
	EntityID          string     `json:"entityId"`
	EntityType        string     `json:"entityType"`
	Score             int        `json:"score"`
	Level             string     `json:"level"`
	BusinessImpact    string     `json:"businessImpact"`
	QuickChecks       int        `json:"quickChecks"`
	DeepChecks        int        `json:"deepChecks"`
	Findings          []string   `json:"findings"`
	Recommendations   []string   `json:"recommendations"`
	Evidence          []Evidence `json:"evidence"`
	EstimatedAPICalls int        `json:"estimatedApiCalls"`
}

type OperationalPolicy struct {
	Decision     string   `json:"decision"`
	Criteria     []string `json:"criteria"`
	NextSteps    []string `json:"nextSteps"`
	Reassessment string   `json:"reassessment"`
}

type DatasetAssessmentSummary struct {
	TotalActionUses          int `json:"totalActionUses"`
	DistinctActions          int `json:"distinctActions"`
	ReposUsingActions        int `json:"reposUsingActions"`
	WorkflowFilesWithActions int `json:"workflowFilesWithActions"`
	HighOrCriticalActions    int `json:"highOrCriticalActions"`
	HighOrCriticalRepos      int `json:"highOrCriticalRepos"`
	EstimatedAPICalls        int `json:"estimatedApiCalls"`
	EstimatedLLMTokens       int `json:"estimatedLlmTokens"`
	EstimatedRuntimeMs       int `json:"estimatedRuntimeMs"`
	EstimatedAnalystMinutes  int `json:"estimatedAnalystMinutes"`
}

type DatasetAssessmentReport struct {
	GeneratedAt                time.Time                `json:"generatedAt"`
	DatasetPath                string                   `json:"datasetPath"`
	RiskModel                  RiskModelDefinition      `json:"riskModel"`
	Summary                    DatasetAssessmentSummary `json:"summary"`
	TopRiskyActions            []RankedRisk             `json:"topRiskyActions"`
	TopSafeActions             []RankedRisk             `json:"topSafeActions"`
	TopRiskyWorkflows          []RankedRisk             `json:"topRiskyWorkflows"`
	TopRiskyRepositories       []RankedRisk             `json:"topRiskyRepositories"`
	TopRiskyBusinessUnits      []RankedRisk             `json:"topRiskyBusinessUnits"`
	TopRiskySoftwareClasses    []RankedRisk             `json:"topRiskySoftwareClasses"`
	PrioritizedRecommendations []string                 `json:"prioritizedRecommendations"`
	OperationalProcess         []OperationalPolicy      `json:"operationalProcess"`
	CostAndScalabilityNotes    []string                 `json:"costAndScalabilityNotes"`
}
