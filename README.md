# ActionTrust
A contextual enterprise control plane for GitHub Actions supply-chain risk: continuous inventory, explainable scoring, workflow blast-radius analysis, and policy-driven gating.

## Backend (Golang)

This repository now includes a production-style backend prototype in Go for CI/CD risk assessment.

### What it does

- Assesses **action-level** GitHub Action trust risk.
- Assesses **workflow-level** GitHub Actions usage risk.
- Produces:
	- explainable findings,
	- weighted risk score,
	- risk level,
	- concrete remediation recommendations,
	- simple cost/scalability estimate.
- Handles incomplete data by separating inferred vs confirmed evidence.

### Project structure

- [cmd/server/main.go](cmd/server/main.go)
- [internal/api/router.go](internal/api/router.go)
- [internal/api/handlers.go](internal/api/handlers.go)
- [internal/engine/scorer.go](internal/engine/scorer.go)
- [internal/models/models.go](internal/models/models.go)
- [internal/store/memory.go](internal/store/memory.go)

### Run locally

1. Ensure Go 1.22+ is installed.
2. From repository root:

	 - `go run ./cmd/server`

3. Service starts on `:8080` by default (or `PORT` env var).

### API endpoints

- `GET /healthz`
- `POST /api/v1/assess`
- `POST /api/v1/assess/actions`
- `POST /api/v1/assess/workflows`
- `POST /api/v1/assess/datasets`
- `GET /api/v1/reports/latest`
- `GET /api/v1/reports/datasets/latest`
- `GET /api/v1/findings?minScore=40&level=high`

### Dataset assessment (hackathon mode)

This backend supports full-dataset assessment directly from repository CSV/JSON files.

`POST /api/v1/assess/datasets`

```json
{
	"basePath": ".",
	"options": {
		"deepAnalysis": true,
		"topN": 15
	}
}
```

Output includes:

- top risky actions,
- top safe actions,
- top risky workflow files extracted from raw usage rows,
- top risky repositories,
- top risky business units,
- top risky software classes,
- explainable checks and evidence,
- cost/scalability estimates,
- operational approval/rejection/exception process.

The dataset pipeline now directly extracts and uses:

- action usage rows from [action_usages.csv](action_usages.csv),
- repository aggregates from [actions_by_repo.csv](actions_by_repo.csv),
- business-unit aggregates from [actions_by_business_unit.csv](actions_by_business_unit.csv),
- software-class aggregates from [actions_by_software_class.csv](actions_by_software_class.csv),
- the high-risk third-party action list from [unpinned_thirdparty_actions.csv](unpinned_thirdparty_actions.csv),
- the overall summary from [summary.json](summary.json).

### Batch CLI

You can generate a report file without running the HTTP server:

- `go run ./cmd/batch -path . -deep=true -top 15 -out report.dataset-assessment.json`

### React dashboard

The repository also includes a React dashboard for categorizing actions and reviewing risk tiers.

- Location: [dashboard/](dashboard)
- Loads data from `GET /api/v1/reports/datasets/latest`
- Includes search, filters, risk bands, and ranked action cards

Run it with:

1. `cd dashboard`
2. `npm install`
3. `npm run dev`

If the backend is not on `http://localhost:8080`, set `VITE_API_BASE_URL`.

### Example request

`POST /api/v1/assess`

```json
{
	"options": { "deepAnalysis": true },
	"actions": [
		{
			"id": "actions/checkout",
			"versionRef": "v4",
			"repoURL": "https://github.com/actions/checkout",
			"pinningStrategy": "tag",
			"usageCount": 250,
			"isFirstParty": true,
			"metadata": {
				"stars": 6000,
				"contributors": 120,
				"archived": false,
				"knownAdvisories": 0,
				"hasSecurityPolicy": true,
				"lastReleaseDays": 45
			}
		}
	],
	"workflows": [
		{
			"id": "repo-a/.github/workflows/build.yml",
			"repository": "repo-a",
			"workflowPath": ".github/workflows/build.yml",
			"triggers": ["pull_request_target"],
			"tokenPermissions": { "contents": "write" },
			"selfHostedRunner": true,
			"secretsExposed": true,
			"untrustedPR": true,
			"usesThirdPartyActions": true,
			"deploymentJob": true,
			"environmentProtected": false,
			"actions": [
				{
					"identifier": "docker/build-push-action",
					"versionRef": "v5",
					"pinningStrategy": "tag",
					"isThirdParty": true
				}
			]
		}
	]
}
```

### Notes

- This backend is intentionally explainable and policy-friendly for hackathon use.
- Risk model weights are configurable in code and easy to tune for TR policy.
- Baseline checks are optimized for organization scale; deep checks are capped to prioritized risk tiers.
