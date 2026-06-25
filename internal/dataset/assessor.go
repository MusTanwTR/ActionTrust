package dataset

// Legacy placeholder retained only to avoid editor churn.

type summarySnapshot struct {
	WorkflowFilesWithActions int `json:"workflow_files_with_actions"`
	ReposUsingActions        int `json:"repos_using_actions"`
	TotalActionUses          int `json:"total_action_uses"`
	DistinctActions          int `json:"distinct_actions"`
}

type actionRow struct {
	Action        string
	SourceType    string
	Kind          string
	TotalUses     int
	DistinctRepos int
	DistinctRefs  int
	PinnedUses    int
	UnpinnedUses  int
	PctPinned     float64
	MostCommonRef string
	AllRefs       string
}

// legacy corrupted content intentionally ignored
