package engine

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"actiontrust/internal/models"
)

func AssessPortfolio(req models.AssessmentRequest) models.AssessmentResponse {
	actionResults := make([]models.AssessmentResult, 0, len(req.Actions))
	workflowResults := make([]models.AssessmentResult, 0, len(req.Workflows))

	for _, a := range req.Actions {
		actionResults = append(actionResults, assessAction(a, req.Options))
	}
	for _, w := range req.Workflows {
		workflowResults = append(workflowResults, assessWorkflow(w, req.Options))
	}

	summary := summarize(actionResults, workflowResults)

	return models.AssessmentResponse{
		GeneratedAt:     time.Now().UTC(),
		ActionResults:   actionResults,
		WorkflowResults: workflowResults,
		Summary:         summary,
		Assumptions: []string{
			"Missing metadata is treated as uncertainty and increases moderate risk.",
			"Risk score is weighted and explainable but should be tuned against TR policy and incident history.",
			"Deep analysis signals estimate external enrichment/API usage cost.",
		},
		Limitations: []string{
			"Current prototype does not execute dynamic sandboxing of actions.",
			"Repository and maintainer trust signals depend on upstream metadata quality.",
			"Workflow script-injection detection requires richer step-level command parsing for maximum precision.",
		},
	}
}

func AssessActions(req models.ActionAssessmentRequest) models.AssessmentResponse {
	portfolioReq := models.AssessmentRequest{Actions: req.Actions, Options: req.Options}
	return AssessPortfolio(portfolioReq)
}

func AssessWorkflows(req models.WorkflowAssessmentRequest) models.AssessmentResponse {
	portfolioReq := models.AssessmentRequest{Workflows: req.Workflows, Options: req.Options}
	return AssessPortfolio(portfolioReq)
}

func assessAction(a models.ActionUsage, opts models.AssessmentOptions) models.AssessmentResult {
	findings := make([]models.RiskFinding, 0, 12)
	quickChecks := 0
	deepChecks := 0

	if a.Denylisted {
		quickChecks++
		findings = append(findings, finding(
			"ACT-DENYLIST",
			"action",
			"Action is denylisted",
			"Action appears in explicit denylist/policy block rules.",
			"critical",
			95,
			true,
			"Block usage and open immediate security review.",
			[]models.Evidence{{Type: "policy", Key: "denylisted", Value: "true", Source: "dataset", Confidence: 1.0}},
		))
	}

	if !a.Allowlisted {
		quickChecks++
		findings = append(findings, finding(
			"ACT-NO-ALLOW",
			"action",
			"Action not explicitly allowlisted",
			"Action is not yet in approved reusable action inventory.",
			"medium",
			15,
			false,
			"Route action to lightweight approval workflow before broad reuse.",
			[]models.Evidence{{Type: "policy", Key: "allowlisted", Value: "false", Source: "dataset", Confidence: 0.8}},
		))
	}

	quickChecks++
	if a.PinningStrategy != models.PinSHA {
		sev := "high"
		score := 30
		if a.PinningStrategy == models.PinTag {
			score = 24
		}
		findings = append(findings, finding(
			"ACT-PINNING",
			"action",
			"Mutable version reference",
			fmt.Sprintf("Action reference uses %q instead of immutable SHA.", a.PinningStrategy),
			sev,
			score,
			true,
			"Pin action to immutable commit SHA and enforce via policy checks.",
			[]models.Evidence{{Type: "config", Key: "pinningStrategy", Value: string(a.PinningStrategy), Source: "dataset", Confidence: 1.0}},
		))
	}

	quickChecks++
	if a.Metadata.Archived {
		findings = append(findings, finding(
			"ACT-ARCHIVED",
			"action",
			"Action repository archived",
			"Archived repositories are likely unmaintained and risky for critical CI/CD use.",
			"high",
			35,
			true,
			"Replace with maintained alternative or mirror internally with strict controls.",
			[]models.Evidence{{Type: "metadata", Key: "archived", Value: "true", Source: "repository", Confidence: 1.0}},
		))
	}

	quickChecks++
	if a.Metadata.KnownAdvisories > 0 {
		findings = append(findings, finding(
			"ACT-ADVISORY",
			"action",
			"Known security advisories detected",
			fmt.Sprintf("Action has %d known advisories.", a.Metadata.KnownAdvisories),
			"critical",
			45,
			true,
			"Block or isolate action until advisories are reviewed and remediated.",
			[]models.Evidence{{Type: "advisory", Key: "knownAdvisories", Value: fmt.Sprintf("%d", a.Metadata.KnownAdvisories), Source: "security-advisory", Confidence: 1.0}},
		))
	}

	quickChecks++
	if a.Metadata.HasSecurityPolicy == nil {
		findings = append(findings, finding(
			"ACT-SEC-POLICY-UNKNOWN",
			"action",
			"Security policy unknown",
			"Repository security policy availability is missing from input data.",
			"medium",
			10,
			false,
			"Run metadata enrichment and prefer actions with explicit SECURITY.md and disclosure process.",
			[]models.Evidence{{Type: "metadata", Key: "hasSecurityPolicy", Value: "unknown", Source: "dataset", Confidence: 0.5}},
		))
	} else if !*a.Metadata.HasSecurityPolicy {
		findings = append(findings, finding(
			"ACT-SEC-POLICY-NONE",
			"action",
			"No security policy",
			"Repository does not publish a security disclosure policy.",
			"medium",
			18,
			true,
			"Prefer alternatives with explicit security process or require internal exception approval.",
			[]models.Evidence{{Type: "metadata", Key: "hasSecurityPolicy", Value: "false", Source: "repository", Confidence: 1.0}},
		))
	}

	quickChecks++
	if a.Metadata.RecentlyRenamed || a.Metadata.RecentlyTransferred {
		findings = append(findings, finding(
			"ACT-OWNERSHIP-CHANGE",
			"action",
			"Recent ownership identity change",
			"Repository rename/transfer can be legitimate but warrants additional trust review.",
			"medium",
			20,
			true,
			"Perform maintainer validation and compare historical release lineage before approval.",
			[]models.Evidence{{Type: "metadata", Key: "renameOrTransfer", Value: "true", Source: "repository", Confidence: 0.9}},
		))
	}

	if opts.DeepAnalysis {
		deepChecks++
		if a.Metadata.MaintainerReputation == nil {
			findings = append(findings, finding(
				"ACT-MAINTAINER-UNKNOWN",
				"action",
				"Maintainer reputation unknown",
				"Maintainer trust profile is missing for this action.",
				"medium",
				12,
				false,
				"Enrich with maintainer trust graph and contributor history before production approval.",
				[]models.Evidence{{Type: "metadata", Key: "maintainerReputation", Value: "unknown", Source: "enrichment", Confidence: 0.4}},
			))
		} else if *a.Metadata.MaintainerReputation < 40 {
			findings = append(findings, finding(
				"ACT-MAINTAINER-LOW",
				"action",
				"Low maintainer trust score",
				fmt.Sprintf("Maintainer reputation score %d/100 is below policy threshold.", *a.Metadata.MaintainerReputation),
				"high",
				28,
				true,
				"Require human approval and consider internally maintained replacement.",
				[]models.Evidence{{Type: "trust", Key: "maintainerReputation", Value: fmt.Sprintf("%d", *a.Metadata.MaintainerReputation), Source: "enrichment", Confidence: 0.9}},
			))
		}

		deepChecks++
		if a.Metadata.DependencyRisk == nil {
			findings = append(findings, finding(
				"ACT-DEPS-UNKNOWN",
				"action",
				"Dependency risk unknown",
				"Dependency tree and vulnerability posture are missing.",
				"medium",
				12,
				false,
				"Run SCA/SBOM analysis and block if critical CVEs exist.",
				[]models.Evidence{{Type: "dependency", Key: "dependencyRisk", Value: "unknown", Source: "sca", Confidence: 0.4}},
			))
		} else if *a.Metadata.DependencyRisk > 70 {
			findings = append(findings, finding(
				"ACT-DEPS-HIGH",
				"action",
				"High dependency risk",
				fmt.Sprintf("Dependency risk score %d/100 indicates elevated supply-chain exposure.", *a.Metadata.DependencyRisk),
				"high",
				34,
				true,
				"Use pinned lockfiles/SBOM verification or replace action.",
				[]models.Evidence{{Type: "dependency", Key: "dependencyRisk", Value: fmt.Sprintf("%d", *a.Metadata.DependencyRisk), Source: "sca", Confidence: 0.9}},
			))
		}

		deepChecks++
		if a.Metadata.SuspiciousRelease {
			findings = append(findings, finding(
				"ACT-RELEASE-SIGNAL",
				"action",
				"Suspicious release activity",
				"Release timing or pattern appears anomalous for this action.",
				"high",
				30,
				true,
				"Require provenance verification, signed artifacts, and manual approval.",
				[]models.Evidence{{Type: "release", Key: "suspiciousRelease", Value: "true", Source: "release-analysis", Confidence: 0.8}},
			))
		}

		deepChecks++
		if a.Metadata.LastReleaseDays > 365 {
			findings = append(findings, finding(
				"ACT-STALE",
				"action",
				"Action appears stale",
				fmt.Sprintf("No recent release in %d days.", a.Metadata.LastReleaseDays),
				"medium",
				16,
				true,
				"Review maintenance status and fallback options.",
				[]models.Evidence{{Type: "release", Key: "lastReleaseDays", Value: fmt.Sprintf("%d", a.Metadata.LastReleaseDays), Source: "repository", Confidence: 0.85}},
			))
		}
	}

	score := clampScore(sumFindings(findings))
	level := scoreToLevel(score)
	recs := recommendations(findings)
	cost := estimateCost(quickChecks, deepChecks)

	return models.AssessmentResult{
		EntityID:        a.ID,
		EntityType:      "action",
		Score:           score,
		Level:           level,
		QuickChecks:     quickChecks,
		DeepChecks:      deepChecks,
		Findings:        findings,
		Recommendations: recs,
		Cost:            cost,
	}
}

func assessWorkflow(w models.WorkflowUsage, opts models.AssessmentOptions) models.AssessmentResult {
	findings := make([]models.RiskFinding, 0, 12)
	quickChecks := 0
	deepChecks := 0

	quickChecks++
	for _, a := range w.Actions {
		if a.PinningStrategy != models.PinSHA {
			findings = append(findings, finding(
				"WF-UNPINNED-ACTION",
				"workflow",
				"Unpinned workflow action",
				fmt.Sprintf("Workflow references %s with mutable strategy %q.", a.Identifier, a.PinningStrategy),
				"high",
				26,
				true,
				"Pin each action to immutable SHA and gate pull requests on pinning policy.",
				[]models.Evidence{{Type: "workflow", Key: "actionPinning", Value: string(a.PinningStrategy), Source: "workflow", Confidence: 1.0}},
			))
		}
	}

	quickChecks++
	if hasOverPermissiveToken(w.TokenPermissions) {
		findings = append(findings, finding(
			"WF-TOKEN-PERMISSIVE",
			"workflow",
			"Over-permissive GITHUB_TOKEN",
			"Workflow token permissions exceed least privilege baseline.",
			"high",
			30,
			true,
			"Set top-level permissions to read-only and grant write only to specific jobs.",
			[]models.Evidence{{Type: "permissions", Key: "tokenPermissions", Value: fmt.Sprintf("%v", w.TokenPermissions), Source: "workflow", Confidence: 0.95}},
		))
	}

	quickChecks++
	if hasTrigger(w.Triggers, "pull_request_target") && w.UntrustedPR {
		findings = append(findings, finding(
			"WF-PRTARGET-UNTRUSTED",
			"workflow",
			"Risky trigger with untrusted PR context",
			"pull_request_target combined with untrusted inputs can allow secret/token abuse.",
			"critical",
			40,
			true,
			"Use pull_request where possible, isolate secrets, and add strict condition guards.",
			[]models.Evidence{{Type: "trigger", Key: "pull_request_target", Value: "true", Source: "workflow", Confidence: 1.0}},
		))
	}

	quickChecks++
	if w.SecretsExposed && (w.UsesThirdPartyActions || hasThirdParty(w.Actions)) {
		findings = append(findings, finding(
			"WF-SECRETS-THIRDPARTY",
			"workflow",
			"Secrets available to third-party actions",
			"Third-party action execution with secrets increases exfiltration blast radius.",
			"critical",
			44,
			true,
			"Split jobs so secrets are only available to trusted first-party steps after validation.",
			[]models.Evidence{{Type: "secret", Key: "secretsExposed", Value: "true", Source: "workflow", Confidence: 0.95}},
		))
	}

	quickChecks++
	if w.SelfHostedRunner && w.UntrustedPR {
		findings = append(findings, finding(
			"WF-SELFHOSTED-PR",
			"workflow",
			"Self-hosted runner exposed to untrusted pull requests",
			"Untrusted code on self-hosted runners can pivot into internal network/resources.",
			"critical",
			45,
			true,
			"Prevent untrusted PR jobs on self-hosted runners or enforce strict isolation.",
			[]models.Evidence{{Type: "runner", Key: "selfHostedRunner", Value: "true", Source: "workflow", Confidence: 1.0}},
		))
	}

	if opts.DeepAnalysis {
		deepChecks++
		if w.UntrustedInputInScript {
			findings = append(findings, finding(
				"WF-SCRIPT-INJECTION",
				"workflow",
				"Potential script injection from untrusted input",
				"Workflow scripts consume untrusted context values without hardening.",
				"high",
				32,
				true,
				"Harden shell usage, quote variables, and avoid direct interpolation of untrusted values.",
				[]models.Evidence{{Type: "script", Key: "untrustedInputInScript", Value: "true", Source: "workflow-analysis", Confidence: 0.85}},
			))
		}

		deepChecks++
		if w.ArtifactFromUntrusted {
			findings = append(findings, finding(
				"WF-ARTIFACT-POISON",
				"workflow",
				"Artifact poisoning risk",
				"Artifacts generated from untrusted context are consumed by privileged jobs.",
				"high",
				34,
				true,
				"Separate untrusted and privileged pipelines, verify artifact integrity/provenance.",
				[]models.Evidence{{Type: "artifact", Key: "artifactFromUntrusted", Value: "true", Source: "workflow-analysis", Confidence: 0.85}},
			))
		}

		deepChecks++
		if w.DeploymentJob && !w.EnvironmentProtected {
			findings = append(findings, finding(
				"WF-DEPLOY-NOGATE",
				"workflow",
				"Deployment without environment approvals",
				"Deployment job does not appear to enforce environment-level approvals or protection.",
				"high",
				29,
				true,
				"Require environment protection rules and separation-of-duty approval gates.",
				[]models.Evidence{{Type: "deployment", Key: "environmentProtected", Value: "false", Source: "workflow", Confidence: 0.9}},
			))
		}
	}

	score := clampScore(sumFindings(findings))
	level := scoreToLevel(score)
	recs := recommendations(findings)
	cost := estimateCost(quickChecks, deepChecks)

	entityID := w.ID
	if strings.TrimSpace(entityID) == "" {
		entityID = fmt.Sprintf("%s:%s", w.Repository, w.WorkflowPath)
	}

	return models.AssessmentResult{
		EntityID:        entityID,
		EntityType:      "workflow",
		Score:           score,
		Level:           level,
		QuickChecks:     quickChecks,
		DeepChecks:      deepChecks,
		Findings:        findings,
		Recommendations: recs,
		Cost:            cost,
	}
}

func summarize(actions, workflows []models.AssessmentResult) models.AssessmentSummary {
	all := append(slices.Clone(actions), workflows...)
	out := models.AssessmentSummary{
		TotalActions:   len(actions),
		TotalWorkflows: len(workflows),
	}

	for _, r := range all {
		out.TotalFindings += len(r.Findings)
		out.EstimatedAPICalls += r.Cost.APICallsEstimated
		out.EstimatedLLMTokens += r.Cost.LLMTokensEstimated
		out.EstimatedRuntimeMs += r.Cost.RuntimeMsEstimated
		out.EstimatedAnalystSaved += r.Cost.AnalystMinutesSaved

		switch r.Level {
		case "critical":
			out.CriticalRisk++
		case "high":
			out.HighRisk++
		case "medium":
			out.MediumRisk++
		default:
			out.LowRisk++
		}
	}

	return out
}

func finding(id, scope, title, description, severity string, score int, confirmed bool, recommendation string, evidence []models.Evidence) models.RiskFinding {
	return models.RiskFinding{
		ID:             id,
		Scope:          scope,
		Title:          title,
		Description:    description,
		Severity:       severity,
		Score:          score,
		Confirmed:      confirmed,
		Recommendation: recommendation,
		Evidence:       evidence,
	}
}

func hasOverPermissiveToken(perms map[string]string) bool {
	if len(perms) == 0 {
		return false
	}
	for k, v := range perms {
		val := strings.ToLower(strings.TrimSpace(v))
		key := strings.ToLower(strings.TrimSpace(k))
		if val == "write" || val == "admin" || val == "*" {
			return true
		}
		if key == "contents" && val == "write" {
			return true
		}
	}
	return false
}

func hasTrigger(triggers []string, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	for _, t := range triggers {
		if strings.ToLower(strings.TrimSpace(t)) == needle {
			return true
		}
	}
	return false
}

func hasThirdParty(actions []models.WorkflowActionRef) bool {
	for _, a := range actions {
		if a.IsThirdParty {
			return true
		}
	}
	return false
}

func sumFindings(findings []models.RiskFinding) int {
	total := 0
	for _, f := range findings {
		total += f.Score
	}
	return total
}

func clampScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func scoreToLevel(score int) string {
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

func recommendations(findings []models.RiskFinding) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		r := strings.TrimSpace(f.Recommendation)
		if r == "" {
			continue
		}
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	slices.Sort(out)
	return out
}

func estimateCost(quickChecks, deepChecks int) models.CostEstimate {
	// Simple transparent cost model for hackathon prioritization.
	api := deepChecks*3 + quickChecks/3
	llm := deepChecks * 1400
	runtimeMs := quickChecks*20 + deepChecks*90
	saved := quickChecks + (deepChecks * 3)
	return models.CostEstimate{
		APICallsEstimated:   api,
		LLMTokensEstimated:  llm,
		RuntimeMsEstimated:  runtimeMs,
		AnalystMinutesSaved: saved,
	}
}
