package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"actiontrust/internal/dataset"
)

func main() {
	basePath := flag.String("path", ".", "Dataset directory path")
	deep := flag.Bool("deep", true, "Enable deep-analysis scoring")
	topN := flag.Int("top", 15, "Top N risky items")
	out := flag.String("out", "report.dataset-assessment.json", "Output JSON report path")
	flag.Parse()

	report, err := dataset.AssessFromDatasets(*basePath, *deep, *topN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "assessment failed: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "create output dir failed: %v\n", err)
		os.Exit(1)
	}

	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create output file failed: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "write output failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Dataset assessment report written to %s\n", *out)
}
