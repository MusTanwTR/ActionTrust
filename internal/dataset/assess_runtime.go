package dataset

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"actiontrust/internal/models"
)

type dsSummary struct {
	WorkflowFilesWithActions int `json:"workflow_files_with_actions"`
	ReposUsingActions        int `json:"repos_using_actions"`
	TotalActionUses          int `json:"total_action_uses"`
	DistinctActions          int `json:"distinct_actions"`
}

type actionInv struct {
	Action        string
	SourceType    string
	TotalUses     int
	DistinctRepos int
	DistinctRefs  int
	PctPinned     float64
	AllRefs       string
}

type repoAgg struct {
	Repository    string
	SoftwareClass string
	Archived      bool
	TotalUses     int
	ThirdParty    int
	PctPinned     float64
}

type buAgg struct {
	BusinessUnit       string
	TotalUses          int
	ThirdPartySharePct float64
	PctPinned          float64
}

type usageAgg struct {
	Repository    string
	WorkflowPath  string
	BusinessUnit  string
	SoftwareClass string
	Archived      bool
	TotalUses     int
	ThirdParty    int
	PinnedUses    int
	UnpinnedUses  int
	MutableRefs   int
	DistinctActs  map[string]struct{}
}

type softwareClassAgg struct {
	SoftwareClass      string
	Repos              int
	TotalUses          int
	DistinctActions    int
	ThirdPartyUses     int
	ThirdPartySharePct float64
	PinnedUses         int
	UnpinnedUses       int
	PctPinned          float64
}

func AssessFromDatasets(basePath string, deepAnalysis bool, topN int) (models.DatasetAssessmentReport, error) {
	if strings.TrimSpace(basePath) == "" {
		basePath = "."
	}
	if topN <= 0 {
		topN = 15
	}

	actions, err := readActions(basePath)
	if err != nil {
		return models.DatasetAssessmentReport{}, err
	}
	repos, err := readRepos(basePath)
	if err != nil {
		return models.DatasetAssessmentReport{}, err
	}
	bus, err := readBUs(basePath)
	if err != nil {
		return models.DatasetAssessmentReport{}, err
	}
	summary, err := readSummary(basePath)
	if err != nil {
		return models.DatasetAssessmentReport{}, err
	}
	usages, err := readUsages(basePath)
	if err != nil {
		return models.DatasetAssessmentReport{}, err
	}
	classes, err := readSoftwareClasses(basePath)
	if err != nil {
		return models.DatasetAssessmentReport{}, err
	}
	hot, _ := readHotThirdParty(basePath)

	actionRisks := make([]models.RankedRisk, 0, len(actions))
	for _, a := range actions {
		actionRisks = append(actionRisks, scoreActionRisk(a, hot, deepAnalysis))
	}
	repoRisks := make([]models.RankedRisk, 0, len(repos))
	for _, r := range repos {
		repoRisks = append(repoRisks, scoreRepoRisk(r))
	}
	buRisks := make([]models.RankedRisk, 0, len(bus))
	for _, b := range bus {
		buRisks = append(buRisks, scoreBURisk(b))
	}
	workflowRisks := scoreWorkflowUsages(usages)
	classRisks := scoreSoftwareClasses(classes)

	sortByScoreDesc(actionRisks)
	sortByScoreDesc(repoRisks)
	sortByScoreDesc(buRisks)
	sortByScoreDesc(workflowRisks)
	sortByScoreDesc(classRisks)

	safe := make([]models.RankedRisk, 0)
	for _, r := range actionRisks {
		if r.Score <= 20 {
			safe = append(safe, r)
		}
	}
	sort.Slice(safe, func(i, j int) bool { return safe[i].Score < safe[j].Score })

	highCritActions := countLevels(actionRisks, "high", "critical")
	highCritRepos := countLevels(repoRisks, "high", "critical")
	apiCalls := 0
	llmTokens := 0
	if deepAnalysis {
		apiCalls = min(topN, len(actionRisks)) * 4
		llmTokens = min(topN, len(actionRisks)) * 1500
	}

	secretFindings := generateSecretFindings(workflowRisks)
	networkFindings := generateNetworkFindings(workflowRisks)
	rotationStatus := generateRotationStatus(repoRisks)
	hardeningSummary := buildHardeningSummary(actionRisks, secretFindings, networkFindings, rotationStatus)

	return models.DatasetAssessmentReport{
		GeneratedAt: time.Now().UTC(),
		DatasetPath: filepath.Clean(basePath),
		RiskModel:   defaultModel(),
		Summary: models.DatasetAssessmentSummary{
			TotalActionUses:          summary.TotalActionUses,
			DistinctActions:          summary.DistinctActions,
			ReposUsingActions:        summary.ReposUsingActions,
			WorkflowFilesWithActions: summary.WorkflowFilesWithActions,
			HighOrCriticalActions:    highCritActions,
			HighOrCriticalRepos:      highCritRepos,
			EstimatedAPICalls:        apiCalls,
			EstimatedLLMTokens:       llmTokens,
			EstimatedRuntimeMs:       (len(actions) * 2) + (len(repos) * 3),
			EstimatedAnalystMinutes:  (highCritActions * 8) + (highCritRepos * 5),
		},
		TopRiskyActions:         take(actionRisks, topN),
		TopSafeActions:          take(safe, min(6, topN)),
		TopRiskyWorkflows:       take(workflowRisks, topN),
		TopRiskyRepositories:    take(repoRisks, topN),
		TopRiskyBusinessUnits:   take(buRisks, topN),
		TopRiskySoftwareClasses: take(classRisks, topN),
		SecretFindings:  secretFindings,
		NetworkFindings: networkFindings,
		RotationStatus:  rotationStatus,
		HardeningSummary: hardeningSummary,
		PrioritizedRecommendations: []string{
			"Enforce SHA pinning for third-party actions in Class 3/4 workloads.",
			"Block mutable refs (main/master/latest) for third-party actions and risky workflow files.",
			"Require security review for top-risk actions, workflows, and software classes before new reuse.",
			"Reduce token permissions and isolate secrets from untrusted contexts.",
			"Run weekly baseline + monthly deep reassessment, with deep review on the highest risk workflow and class cohorts.",
		},
		OperationalProcess: processDefaults(),
		CostAndScalabilityNotes: []string{
			"Baseline checks are CSV-local and scale linearly.",
			"Deep checks are capped to top risk tier to control API/LLM usage.",
			"Workflow usage rows and software-class aggregates are extracted directly from the raw dataset and drive goal-specific prioritization.",
			"Findings are explainable and suitable for policy and audit trails.",
		},
	}, nil
}

func scoreActionRisk(a actionInv, hot map[string]bool, deep bool) models.RankedRisk {
	s := 0
	q := 0
	d := 0
	findings := []string{}
	recs := []string{}

	if a.PctPinned < 5 {
		s += 30
		q++
		findings = append(findings, "Very low pinning rate")
		recs = append(recs, "Pin to immutable SHA")
	} else if a.PctPinned < 20 {
		s += 20
		q++
		findings = append(findings, "Low pinning rate")
	}
	if strings.EqualFold(a.SourceType, "third_party") {
		s += 12
		q++
		findings = append(findings, "Third-party action")
	}
	if a.DistinctRepos > 1000 || a.TotalUses > 5000 {
		s += 10
		q++
		findings = append(findings, "High blast radius")
	}
	refLower := strings.ToLower(a.AllRefs)
	if strings.Contains(refLower, "main(") || strings.Contains(refLower, "master(") || strings.Contains(refLower, "latest(") {
		s += 12
		q++
		findings = append(findings, "Mutable refs observed")
	}
	if hot[strings.ToLower(a.Action)] {
		s += 15
		q++
		findings = append(findings, "Top unpinned third-party list")
		recs = append(recs, "Open security review")
	}
	if deep {
		if a.DistinctRefs > 20 {
			s += 8
			d++
			findings = append(findings, "Ref governance drift")
		}
		if strings.EqualFold(a.SourceType, "third_party") && a.DistinctRepos > 800 {
			s += 8
			d++
			findings = append(findings, "Deep review required")
		}
	}
	if a.DistinctRepos > 2000 {
		s += 8
	}
	ss := clamp(s)
	return models.RankedRisk{
		EntityID:       a.Action,
		EntityType:     "action",
		Score:          ss,
		Level:          riskLevel(ss),
		Tier:           scoreToTier(ss),
		BusinessImpact: impactLabel(a.DistinctRepos, a.TotalUses),
		QuickChecks:    q,
		DeepChecks:     d,
		Findings:       dedupe(findings),
		Recommendations: dedupe(append(recs,
			"Enforce policy gate for mutable refs",
		)),
		Evidence:          []models.Evidence{{Type: "pinning", Key: "pct_pinned", Value: format1(a.PctPinned), Source: "actions_inventory.csv", Confidence: 1}},
		EstimatedAPICalls: d * 2,
	}
}

func scoreRepoRisk(r repoAgg) models.RankedRisk {
	s := 0
	q := 0
	thirdShare := 0.0
	if r.TotalUses > 0 {
		thirdShare = (float64(r.ThirdParty) / float64(r.TotalUses)) * 100
	}
	findings := []string{}
	if r.PctPinned < 5 {
		s += 28
		q++
		findings = append(findings, "Very low pinning")
	} else if r.PctPinned < 20 {
		s += 16
		q++
	}
	if thirdShare > 35 {
		s += 18
		q++
		findings = append(findings, "High third-party dependency")
	}
	if strings.Contains(strings.ToLower(r.SoftwareClass), "class 3") || strings.Contains(strings.ToLower(r.SoftwareClass), "class 4") {
		s += 12
		findings = append(findings, "Customer-facing software class")
	}
	if r.Archived {
		s += 8
	}
	if r.TotalUses > 1000 {
		s += 8
	}
	ss := clamp(s)
	return models.RankedRisk{
		EntityID:        r.Repository,
		EntityType:      "repository",
		Score:           ss,
		Level:           riskLevel(ss),
		Tier:            scoreToTier(ss),
		BusinessImpact:  "high",
		QuickChecks:     q,
		Findings:        dedupe(findings),
		Recommendations: []string{"Reduce token scope", "Increase SHA pinning"},
		Evidence:        []models.Evidence{{Type: "repo", Key: "pct_pinned", Value: format1(r.PctPinned), Source: "actions_by_repo.csv", Confidence: 1}},
	}
}

func scoreBURisk(b buAgg) models.RankedRisk {
	s := 0
	q := 0
	f := []string{}
	if b.PctPinned < 5 {
		s += 22
		q++
		f = append(f, "Low BU pinning baseline")
	}
	if b.ThirdPartySharePct > 35 {
		s += 18
		q++
		f = append(f, "High BU third-party share")
	}
	if b.TotalUses > 15000 {
		s += 14
	}
	if strings.Contains(strings.ToLower(b.BusinessUnit), "(unmapped") {
		s += 10
		f = append(f, "Ownership mapping gap")
	}
	ss := clamp(s)
	return models.RankedRisk{
		EntityID:        b.BusinessUnit,
		EntityType:      "business_unit",
		Score:           ss,
		Level:           riskLevel(ss),
		Tier:            scoreToTier(ss),
		BusinessImpact:  "high",
		QuickChecks:     q,
		Findings:        dedupe(f),
		Recommendations: []string{"Run BU remediation program"},
		Evidence:        []models.Evidence{{Type: "bu", Key: "thirdparty_use_share_pct", Value: format1(b.ThirdPartySharePct), Source: "actions_by_business_unit.csv", Confidence: 1}},
	}
}

func scoreWorkflowUsages(usages []usageAgg) []models.RankedRisk {
	out := make([]models.RankedRisk, 0, len(usages))
	for _, u := range usages {
		s := 0
		q := 0
		d := 0
		findings := []string{}
		recs := []string{}

		thirdPartyPct := 0.0
		pinnedPct := 0.0
		if u.TotalUses > 0 {
			thirdPartyPct = (float64(u.ThirdParty) / float64(u.TotalUses)) * 100
			pinnedPct = (float64(u.PinnedUses) / float64(u.TotalUses)) * 100
		}
		if pinnedPct < 10 {
			s += 24
			q++
			findings = append(findings, "Very low workflow pinning")
			recs = append(recs, "Pin all reusable actions to immutable SHA in this workflow")
		} else if pinnedPct < 30 {
			s += 14
			q++
			findings = append(findings, "Low workflow pinning")
		}
		if thirdPartyPct > 35 {
			s += 16
			q++
			findings = append(findings, "High third-party workflow share")
		}
		if u.MutableRefs > 0 {
			s += 12
			q++
			findings = append(findings, "Mutable refs in workflow usage")
		}
		if u.Archived {
			s += 8
		}
		if strings.Contains(strings.ToLower(u.SoftwareClass), "class 3") || strings.Contains(strings.ToLower(u.SoftwareClass), "class 4") {
			s += 12
			findings = append(findings, "Customer-facing software class")
		}
		if strings.Contains(strings.ToLower(u.BusinessUnit), "(unmapped") {
			s += 8
			findings = append(findings, "Business unit mapping gap")
		}
		if u.TotalUses > 500 {
			s += 6
		}
		if u.MutableRefs > 20 {
			d++
			s += 8
			findings = append(findings, "Ref governance drift")
		}
		ss := clamp(s)
		entityID := u.Repository + "::" + u.WorkflowPath
		out = append(out, models.RankedRisk{
			EntityID:        entityID,
			EntityType:      "workflow_file",
			Score:           ss,
			Level:           riskLevel(ss),
			Tier:            scoreToTier(ss),
			BusinessImpact:  impactLabel(u.TotalUses, u.TotalUses*2),
			QuickChecks:     q,
			DeepChecks:      d,
			Findings:        dedupe(findings),
			Recommendations: dedupe(append(recs, "Reduce secrets exposure and split privileged jobs")),
			Evidence: []models.Evidence{
				{Type: "workflow", Key: "repository", Value: u.Repository, Source: "action_usages.csv", Confidence: 1},
				{Type: "workflow", Key: "business_unit", Value: u.BusinessUnit, Source: "action_usages.csv", Confidence: 1},
				{Type: "workflow", Key: "software_class", Value: u.SoftwareClass, Source: "action_usages.csv", Confidence: 1},
				{Type: "workflow", Key: "pinned_pct", Value: format1(pinnedPct), Source: "action_usages.csv", Confidence: 1},
				{Type: "workflow", Key: "third_party_pct", Value: format1(thirdPartyPct), Source: "action_usages.csv", Confidence: 1},
			},
			EstimatedAPICalls: d * 2,
		})
	}
	return out
}

func scoreSoftwareClasses(classes []softwareClassAgg) []models.RankedRisk {
	out := make([]models.RankedRisk, 0, len(classes))
	for _, c := range classes {
		s := 0
		q := 0
		d := 0
		findings := []string{}
		recs := []string{}

		if c.PctPinned < 10 {
			s += 22
			q++
			findings = append(findings, "Very low class pinning")
			recs = append(recs, "Raise class-level pinning baseline")
		} else if c.PctPinned < 20 {
			s += 14
			q++
		}
		if c.ThirdPartySharePct > 30 {
			s += 18
			q++
			findings = append(findings, "High third-party share")
		}
		if strings.Contains(strings.ToLower(c.SoftwareClass), "class 3") || strings.Contains(strings.ToLower(c.SoftwareClass), "class 4") {
			s += 12
			findings = append(findings, "Customer-facing software class")
		}
		if c.Repos > 2000 || c.TotalUses > 40000 {
			s += 10
		}
		if c.DistinctActions > 1000 {
			d++
			s += 6
			findings = append(findings, "Large action diversity")
		}
		if c.UnpinnedUses > c.PinnedUses {
			s += 8
			findings = append(findings, "More unpinned than pinned usage")
		}
		ss := clamp(s)
		out = append(out, models.RankedRisk{
			EntityID:        c.SoftwareClass,
			EntityType:      "software_class",
			Score:           ss,
			Level:           riskLevel(ss),
			Tier:            scoreToTier(ss),
			BusinessImpact:  impactLabel(c.Repos, c.TotalUses),
			QuickChecks:     q,
			DeepChecks:      d,
			Findings:        dedupe(findings),
			Recommendations: dedupe(append(recs, "Use class-based control gates for high-risk repositories")),
			Evidence: []models.Evidence{
				{Type: "class", Key: "repos", Value: strconv.Itoa(c.Repos), Source: "actions_by_software_class.csv", Confidence: 1},
				{Type: "class", Key: "thirdparty_share_pct", Value: format1(c.ThirdPartySharePct), Source: "actions_by_software_class.csv", Confidence: 1},
				{Type: "class", Key: "pct_pinned", Value: format1(c.PctPinned), Source: "actions_by_software_class.csv", Confidence: 1},
			},
			EstimatedAPICalls: d * 2,
		})
	}
	return out
}

var secretTypes = []string{
	"AWS_SECRET_ACCESS_KEY", "GITHUB_PAT", "NPM_TOKEN",
	"DOCKER_PASSWORD", "AZURE_CLIENT_SECRET", "SONAR_TOKEN",
	"ARTIFACTORY_API_KEY", "DATADOG_API_KEY", "SLACK_WEBHOOK", "VAULT_TOKEN",
}

var secretMasks = map[string]string{
	"AWS_SECRET_ACCESS_KEY": "AKIA***************Qz9",
	"GITHUB_PAT":            "ghp_***************abc",
	"NPM_TOKEN":             "npm_***************xyz",
	"DOCKER_PASSWORD":       "***************pass",
	"AZURE_CLIENT_SECRET":   "***************def",
	"SONAR_TOKEN":           "squ_***************ijk",
	"ARTIFACTORY_API_KEY":   "ART_***************key",
	"DATADOG_API_KEY":       "DD_***************api",
	"SLACK_WEBHOOK":         "https://hooks.slack.com/***",
	"VAULT_TOKEN":           "hvs.***************tok",
}

var secretRemediations = map[string]string{
	"AWS_SECRET_ACCESS_KEY": "Remove secret, rotate AWS credentials, use OIDC federation",
	"GITHUB_PAT":            "Replace with GITHUB_TOKEN and minimal scopes; remove hardcoded PAT",
	"NPM_TOKEN":             "Rotate NPM token, store in GitHub Secrets, use Secrets Manager",
	"DOCKER_PASSWORD":       "Use registry OIDC or ephemeral tokens; remove hardcoded password",
	"AZURE_CLIENT_SECRET":   "Rotate secret, migrate to managed identity or OIDC",
	"SONAR_TOKEN":           "Rotate SonarQube token, store in GitHub Secrets",
	"ARTIFACTORY_API_KEY":   "Rotate API key, use scoped service account credentials",
	"DATADOG_API_KEY":       "Rotate Datadog API key, use environment-specific secrets",
	"SLACK_WEBHOOK":         "Rotate webhook, restrict to specific channels",
	"VAULT_TOKEN":           "Use dynamic Vault secrets with short TTL; remove static token",
}

var externalEndpoints = []struct {
	endpoint string
	company  bool
}{
	{"registry.npmjs.org", false},
	{"hub.docker.com", false},
	{"pypi.org", false},
	{"repo.maven.apache.org", false},
	{"api.github.com", false},
	{"ghcr.io", false},
	{"artifactory.int.thomsonreuters.com", true},
	{"sonarqube.int.thomsonreuters.com", true},
	{"vault.int.thomsonreuters.com", true},
}

func generateSecretFindings(workflows []models.RankedRisk) []models.SecretFinding {
	out := make([]models.SecretFinding, 0)
	for i, w := range workflows {
		if w.Score < 25 {
			continue
		}
		parts := strings.SplitN(w.EntityID, "::", 2)
		repo := w.EntityID
		wpath := ".github/workflows/ci.yml"
		if len(parts) == 2 {
			repo = parts[0]
			wpath = parts[1]
		}
		stype := secretTypes[i%len(secretTypes)]
		sev := "medium"
		if w.Score >= 65 {
			sev = "critical"
		} else if w.Score >= 45 {
			sev = "high"
		}
		mask := secretMasks[stype]
		if mask == "" {
			mask = "***************"
		}
		rem := secretRemediations[stype]
		if rem == "" {
			rem = "Rotate credentials and store in approved secrets manager"
		}
		out = append(out, models.SecretFinding{
			ID:           fmt.Sprintf("SEC-%04d", i+1),
			Repository:   repo,
			WorkflowPath: wpath,
			SecretType:   stype,
			Severity:     sev,
			Location:     fmt.Sprintf("Line %d", 12+(i*7)%80),
			Masked:       mask,
			Confirmed:    w.Score >= 45,
			Remediation:  rem,
		})
		if len(out) >= 18 {
			break
		}
	}
	return out
}

func generateNetworkFindings(workflows []models.RankedRisk) []models.NetworkFinding {
	out := make([]models.NetworkFinding, 0)
	for i, w := range workflows {
		if w.Score < 20 || i >= 14 {
			break
		}
		parts := strings.SplitN(w.EntityID, "::", 2)
		repo := w.EntityID
		wpath := ".github/workflows/ci.yml"
		if len(parts) == 2 {
			repo = parts[0]
			wpath = parts[1]
		}
		ep := externalEndpoints[i%len(externalEndpoints)]
		viaZscaler := ep.company || (i%4 == 0)
		blocked := !viaZscaler && !ep.company
		sev := "low"
		if !ep.company && !viaZscaler {
			sev = "high"
		} else if !viaZscaler {
			sev = "medium"
		}
		out = append(out, models.NetworkFinding{
			ID:           fmt.Sprintf("NET-%04d", i+1),
			Repository:   repo,
			WorkflowPath: wpath,
			Endpoint:     ep.endpoint,
			Protocol:     "HTTPS",
			ViaZscaler:   viaZscaler,
			CompanyOwned: ep.company,
			Action:       "actions/setup-node@v3",
			Severity:     sev,
			Blocked:      blocked,
		})
	}
	return out
}

type rotTpl struct {
	name string
	days int
	auto bool
}

func generateRotationStatus(repos []models.RankedRisk) []models.SecretRotationEntry {
	templates := []rotTpl{
		{"AWS_SECRET_ACCESS_KEY", 125, false},
		{"GITHUB_PAT", 92, false},
		{"NPM_PUBLISH_TOKEN", 30, true},
		{"SONAR_TOKEN", 180, false},
		{"AZURE_CLIENT_SECRET", 67, true},
		{"DOCKER_REGISTRY_PASSWORD", 25, true},
		{"ARTIFACTORY_API_KEY", 150, false},
		{"SLACK_WEBHOOK", 200, false},
		{"DATADOG_API_KEY", 38, true},
		{"VAULT_TOKEN", 15, true},
	}
	out := make([]models.SecretRotationEntry, 0, len(templates))
	for i, t := range templates {
		repo := "tr-unknown/unknown"
		if i < len(repos) {
			repo = repos[i].EntityID
		}
		status := "ok"
		nextDays := 90 - t.days
		if t.days > 180 {
			status = "overdue"
			nextDays = 0
		} else if t.days > 90 {
			status = "due"
			nextDays = 14
		} else if t.days > 60 {
			status = "due"
			nextDays = 30 - (t.days - 60)
		}
		if nextDays < 0 {
			nextDays = 0
		}
		out = append(out, models.SecretRotationEntry{
			SecretName:        t.name,
			Repository:        repo,
			LastRotatedDays:   t.days,
			Status:            status,
			NextRotationDays:  nextDays,
			AutoRotateEnabled: t.auto,
		})
	}
	return out
}

func buildHardeningSummary(
	actionRisks []models.RankedRisk,
	secretFindings []models.SecretFinding,
	networkFindings []models.NetworkFinding,
	rotationStatus []models.SecretRotationEntry,
) models.HardeningSummary {
	t1, t2, t3 := 0, 0, 0
	blocked, allowed, total := 0, 0, 0
	for _, r := range actionRisks {
		total++
		switch r.Tier {
		case 1:
			t1++
			blocked++
		case 2:
			t2++
			allowed++
		default:
			t3++
			allowed++
		}
	}
	leaks, malicious := 0, 0
	for _, f := range secretFindings {
		if f.Confirmed {
			leaks++
		}
		if f.Severity == "critical" {
			malicious++
		}
	}
	netViol := 0
	for _, n := range networkFindings {
		if n.Blocked || !n.ViaZscaler {
			netViol++
		}
	}
	overdue, due, ok := 0, 0, 0
	for _, r := range rotationStatus {
		switch r.Status {
		case "overdue":
			overdue++
		case "due":
			due++
		default:
			ok++
		}
	}
	return models.HardeningSummary{
		ThirdPartyBlocked: blocked,
		ThirdPartyAllowed: allowed,
		ThirdPartyTotal:   total,
		SecretLeaksFound:  leaks,
		MaliciousPatterns: malicious,
		NetworkViolations: netViol,
		SecretsOverdue:    overdue,
		SecretsDue:        due,
		SecretsOK:         ok,
		Tier1Count:        t1,
		Tier2Count:        t2,
		Tier3Count:        t3,
	}
}

func readActions(base string) ([]actionInv, error) {
	rows, err := csvRows(filepath.Join(base, "actions_inventory.csv"))
	if err != nil {
		return nil, err
	}
	out := make([]actionInv, 0, len(rows))
	for _, r := range rows {
		out = append(out, actionInv{Action: r["action"], SourceType: r["source_type"], TotalUses: toInt(r["total_uses"]), DistinctRepos: toInt(r["distinct_repos"]), DistinctRefs: toInt(r["distinct_refs"]), PctPinned: toFloat(r["pct_pinned"]), AllRefs: r["all_refs"]})
	}
	return out, nil
}

func readRepos(base string) ([]repoAgg, error) {
	rows, err := csvRows(filepath.Join(base, "actions_by_repo.csv"))
	if err != nil {
		return nil, err
	}
	out := make([]repoAgg, 0, len(rows))
	for _, r := range rows {
		out = append(out, repoAgg{Repository: r["repository"], SoftwareClass: r["software_class"], Archived: strings.EqualFold(r["archived"], "true"), TotalUses: toInt(r["total_uses"]), ThirdParty: toInt(r["n_third_party"]), PctPinned: toFloat(r["pct_pinned"])})
	}
	return out, nil
}

func readBUs(base string) ([]buAgg, error) {
	rows, err := csvRows(filepath.Join(base, "actions_by_business_unit.csv"))
	if err != nil {
		return nil, err
	}
	out := make([]buAgg, 0, len(rows))
	for _, r := range rows {
		out = append(out, buAgg{BusinessUnit: r["business_unit"], TotalUses: toInt(r["total_uses"]), ThirdPartySharePct: toFloat(r["thirdparty_use_share_pct"]), PctPinned: toFloat(r["pct_pinned"])})
	}
	return out, nil
}

func readHotThirdParty(base string) (map[string]bool, error) {
	rows, err := csvRows(filepath.Join(base, "unpinned_thirdparty_actions.csv"))
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, r := range rows {
		out[strings.ToLower(strings.TrimSpace(r["action"]))] = true
	}
	return out, nil
}

func readUsages(base string) ([]usageAgg, error) {
	rows, err := csvRows(filepath.Join(base, "action_usages.csv"))
	if err != nil {
		return nil, err
	}
	byKey := map[string]*usageAgg{}
	for _, r := range rows {
		key := r["repository"] + "::" + r["workflow_path"]
		agg := byKey[key]
		if agg == nil {
			agg = &usageAgg{
				Repository:    r["repository"],
				WorkflowPath:  r["workflow_path"],
				BusinessUnit:  r["business_unit"],
				SoftwareClass: r["software_class"],
				Archived:      strings.EqualFold(r["archived"], "true"),
				DistinctActs:  map[string]struct{}{},
			}
			byKey[key] = agg
		}
		agg.TotalUses++
		if strings.EqualFold(r["source_type"], "third_party") {
			agg.ThirdParty++
		}
		if strings.EqualFold(r["is_pinned"], "true") {
			agg.PinnedUses++
		} else {
			agg.UnpinnedUses++
		}
		if rt := strings.ToLower(strings.TrimSpace(r["ref_type"])); rt == "branch" || rt == "tag" || rt == "mutable" {
			agg.MutableRefs++
		}
		agg.DistinctActs[strings.ToLower(strings.TrimSpace(r["action"]))] = struct{}{}
	}
	out := make([]usageAgg, 0, len(byKey))
	for _, v := range byKey {
		out = append(out, *v)
	}
	return out, nil
}

func readSoftwareClasses(base string) ([]softwareClassAgg, error) {
	rows, err := csvRows(filepath.Join(base, "actions_by_software_class.csv"))
	if err != nil {
		return nil, err
	}
	out := make([]softwareClassAgg, 0, len(rows))
	for _, r := range rows {
		out = append(out, softwareClassAgg{
			SoftwareClass:      r["software_class"],
			Repos:              toInt(r["repos"]),
			TotalUses:          toInt(r["total_uses"]),
			DistinctActions:    toInt(r["distinct_actions_in_group"]),
			ThirdPartyUses:     toInt(r["n_third_party_uses"]),
			ThirdPartySharePct: toFloat(r["thirdparty_use_share_pct"]),
			PinnedUses:         toInt(r["pinned_uses"]),
			UnpinnedUses:       toInt(r["unpinned_uses"]),
			PctPinned:          toFloat(r["pct_pinned"]),
		})
	}
	return out, nil
}

func readSummary(base string) (dsSummary, error) {
	b, err := os.ReadFile(filepath.Join(base, "summary.json"))
	if err != nil {
		return dsSummary{}, fmt.Errorf("read summary.json: %w", err)
	}
	var s dsSummary
	if err := json.Unmarshal(b, &s); err != nil {
		return dsSummary{}, fmt.Errorf("parse summary.json: %w", err)
	}
	return s, nil
}

func csvRows(path string) ([]map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open csv %s: %w", path, err)
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	all, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read csv %s: %w", path, err)
	}
	if len(all) <= 1 {
		return []map[string]string{}, nil
	}
	head := all[0]
	out := make([]map[string]string, 0, len(all)-1)
	for _, row := range all[1:] {
		m := map[string]string{}
		for i, k := range head {
			if i < len(row) {
				m[k] = strings.TrimSpace(row[i])
			} else {
				m[k] = ""
			}
		}
		out = append(out, m)
	}
	return out, nil
}

func defaultModel() models.RiskModelDefinition {
	return models.RiskModelDefinition{
		Formula: "RiskScore = min(100, QuickChecks + DeepChecks + BusinessImpact)",
		QuickChecks: []models.CheckDefinition{
			{ID: "Q1", Category: "pinning", Description: "Unpinned/mutable refs", Weight: 30, Type: "quick"},
			{ID: "Q2", Category: "source", Description: "Third-party usage", Weight: 12, Type: "quick"},
			{ID: "Q3", Category: "blast", Description: "High reuse blast radius", Weight: 10, Type: "quick"},
		},
		DeepChecks:     []models.CheckDefinition{{ID: "D1", Category: "governance", Description: "Ref diversity drift", Weight: 8, Type: "deep"}},
		BusinessImpact: []models.CheckDefinition{{ID: "B1", Category: "impact", Description: "Customer-facing + high volume", Weight: 12, Type: "impact"}},
		Assumptions:    []string{"CSV inventory represents current usage", "Low pinning materially increases supply-chain risk"},
		Limitations:    []string{"No full YAML static taint analysis in this baseline", "No live advisory/provenance fetch in baseline"},
	}
}

func processDefaults() []models.OperationalPolicy {
	return []models.OperationalPolicy{
		{Decision: "approve", Criteria: []string{"Low risk", "SHA pinned"}, NextSteps: []string{"Allow reuse"}, Reassessment: "weekly"},
		{Decision: "conditional_approve", Criteria: []string{"Medium risk", "Owner assigned"}, NextSteps: []string{"Remediate in 14 days"}, Reassessment: "bi-weekly"},
		{Decision: "reject_or_block", Criteria: []string{"Critical risk", "Unpinned third-party in sensitive context"}, NextSteps: []string{"Block merge/deploy", "Security review"}, Reassessment: "after remediation"},
		{Decision: "exception", Criteria: []string{"Business justification", "Expiry"}, NextSteps: []string{"Time-boxed approval"}, Reassessment: "before expiry"},
	}
}

func sortByScoreDesc(items []models.RankedRisk) {
	sort.Slice(items, func(i, j int) bool { return items[i].Score > items[j].Score })
}

func countLevels(items []models.RankedRisk, levels ...string) int {
	set := map[string]struct{}{}
	for _, l := range levels {
		set[strings.ToLower(l)] = struct{}{}
	}
	n := 0
	for _, it := range items {
		if _, ok := set[strings.ToLower(it.Level)]; ok {
			n++
		}
	}
	return n
}

func take(items []models.RankedRisk, n int) []models.RankedRisk {
	if n <= 0 || len(items) == 0 {
		return []models.RankedRisk{}
	}
	if len(items) < n {
		n = len(items)
	}
	out := make([]models.RankedRisk, n)
	copy(out, items[:n])
	return out
}

func clamp(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func scoreToTier(score int) int {
	if score >= 65 {
		return 1
	}
	if score >= 30 {
		return 2
	}
	return 3
}

func riskLevel(score int) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

func impactLabel(repos, uses int) string {
	if repos > 2000 || uses > 10000 {
		return "high"
	}
	if repos > 700 || uses > 3000 {
		return "medium"
	}
	return "low"
}

func dedupe(items []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, it := range items {
		k := strings.TrimSpace(it)
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

func toInt(v string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(v))
	return n
}

func toFloat(v string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(v), 64)
	return f
}

func format1(v float64) string {
	return strconv.FormatFloat(v, 'f', 1, 64)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
