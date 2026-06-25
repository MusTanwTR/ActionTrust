package api

import (
	"net/http"
)

func NewRouter(h *Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.Healthz)
	mux.HandleFunc("POST /api/v1/assess", h.AssessAll)
	mux.HandleFunc("POST /api/v1/assess/actions", h.AssessActions)
	mux.HandleFunc("POST /api/v1/assess/workflows", h.AssessWorkflows)
	mux.HandleFunc("POST /api/v1/assess/datasets", h.AssessDatasets)
	mux.HandleFunc("GET /api/v1/reports/latest", h.LatestReport)
	mux.HandleFunc("GET /api/v1/reports/datasets/latest", h.LatestDatasetReport)
	mux.HandleFunc("GET /api/v1/findings", h.Findings)
	return withCORS(mux)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
