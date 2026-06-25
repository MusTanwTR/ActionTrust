package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"actiontrust/internal/dataset"
	"actiontrust/internal/engine"
	"actiontrust/internal/models"
	"actiontrust/internal/store"
)

type Handler struct {
	Store *store.MemoryStore
}

func NewHandler(s *store.MemoryStore) *Handler {
	return &Handler{Store: s}
}

func (h *Handler) Healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) AssessAll(w http.ResponseWriter, r *http.Request) {
	var req models.AssessmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	resp := engine.AssessPortfolio(req)
	h.Store.SaveLatest(resp)
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) AssessActions(w http.ResponseWriter, r *http.Request) {
	var req models.ActionAssessmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	resp := engine.AssessActions(req)
	h.Store.SaveLatest(resp)
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) AssessWorkflows(w http.ResponseWriter, r *http.Request) {
	var req models.WorkflowAssessmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	resp := engine.AssessWorkflows(req)
	h.Store.SaveLatest(resp)
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) LatestReport(w http.ResponseWriter, _ *http.Request) {
	report, ok := h.Store.Latest()
	if !ok {
		writeError(w, http.StatusNotFound, "no report available")
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (h *Handler) Findings(w http.ResponseWriter, r *http.Request) {
	report, ok := h.Store.Latest()
	if !ok {
		writeError(w, http.StatusNotFound, "no report available")
		return
	}

	minScore := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("minScore")); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "minScore must be integer")
			return
		}
		minScore = v
	}
	level := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("level")))

	findings := make([]models.RiskFinding, 0)
	collect := func(results []models.AssessmentResult) {
		for _, rs := range results {
			for _, f := range rs.Findings {
				if f.Score < minScore {
					continue
				}
				if level != "" && strings.ToLower(f.Severity) != level {
					continue
				}
				findings = append(findings, f)
			}
		}
	}
	collect(report.ActionResults)
	collect(report.WorkflowResults)
	writeJSON(w, http.StatusOK, map[string]any{"count": len(findings), "findings": findings})
}

func (h *Handler) AssessDatasets(w http.ResponseWriter, r *http.Request) {
	var req models.DatasetAssessmentRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	basePath := strings.TrimSpace(req.BasePath)
	if basePath == "" {
		cwd, err := os.Getwd()
		if err == nil {
			basePath = cwd
		}
	}
	if basePath == "" {
		basePath = "."
	}
	basePath = filepath.Clean(basePath)

	topN := req.Options.TopN
	if topN <= 0 {
		topN = 15
	}
	report, err := dataset.AssessFromDatasets(basePath, req.Options.DeepAnalysis, topN)
	if err != nil {
		writeError(w, http.StatusBadRequest, "dataset assessment failed: "+err.Error())
		return
	}

	h.Store.SaveLatestDataset(report)
	writeJSON(w, http.StatusOK, report)
}

func (h *Handler) LatestDatasetReport(w http.ResponseWriter, _ *http.Request) {
	report, ok := h.Store.LatestDataset()
	if !ok {
		writeError(w, http.StatusNotFound, "no dataset report available")
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func writeError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
