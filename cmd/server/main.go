package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"actiontrust/internal/api"
	"actiontrust/internal/store"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	st := store.NewMemoryStore()
	h := api.NewHandler(st)
	router := api.NewRouter(h)

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("ActionTrust backend listening on :%s", port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server failed: %v", err)
	}
}
