// Command sentra-bench measures analyzer latency and throughput on a corpus.
//
//	go run ./cmd/sentra-bench -corpus /path/to/repo [-workers N] [-runs 3] [-json out.json]
//
// It reports per-file latency percentiles (single-threaded), lines/sec, and
// wall-clock time to scan the whole corpus with N workers (the workspace-scan
// path). Files are read into memory first so disk I/O is excluded.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"sentra-analyzer/internal/engine"
)

type file struct {
	path  string
	lang  engine.Language
	src   []byte
	lines int
}

// Report is the JSON output.
type Report struct {
	Corpus        string             `json:"corpus"`
	Files         int                `json:"files"`
	Lines         int                `json:"lines"`
	Bytes         int                `json:"bytes"`
	Findings      int                `json:"findings"`
	LatencyMs     map[string]float64 `json:"latency_ms"`
	SerialSec     float64            `json:"serial_sec"`
	LinesPerSec   float64            `json:"lines_per_sec_single_thread"`
	Workers       int                `json:"workers"`
	ParallelSec   float64            `json:"parallel_sec_best"`
	ParallelRuns  []float64          `json:"parallel_sec_runs"`
	LinesPerSecMT float64            `json:"lines_per_sec_parallel"`
	GoVersion     string             `json:"go_version"`
	NumCPU        int                `json:"num_cpu"`
	OS            string             `json:"os_arch"`
}

func main() {
	corpus := flag.String("corpus", "", "directory to scan")
	workers := flag.Int("workers", runtime.NumCPU(), "parallel workers")
	runs := flag.Int("runs", 3, "parallel runs (best is reported)")
	maxSize := flag.Int64("max-size", 1<<20, "skip files larger than this (bytes), like the extension")
	jsonOut := flag.String("json", "", "write the report as JSON to this file")
	flag.Parse()
	if *corpus == "" {
		flag.Usage()
		os.Exit(2)
	}

	files, err := load(*corpus, *maxSize)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	eng := engine.Default()
	// Warm up: load the model, create one parser per language.
	for _, f := range files[:min(len(files), 50)] {
		_, _ = eng.Analyze(f.lang, f.src)
	}

	r := Report{Corpus: *corpus, Files: len(files), Workers: *workers,
		GoVersion: runtime.Version(), NumCPU: runtime.NumCPU(), OS: runtime.GOOS + "/" + runtime.GOARCH}
	lat := make([]time.Duration, len(files))
	start := time.Now()
	for i, f := range files {
		t0 := time.Now()
		findings, _ := eng.Analyze(f.lang, f.src)
		lat[i] = time.Since(t0)
		r.Findings += len(findings)
		r.Lines += f.lines
		r.Bytes += len(f.src)
	}
	r.SerialSec = time.Since(start).Seconds()
	r.LinesPerSec = float64(r.Lines) / r.SerialSec
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	pct := func(p float64) float64 {
		return float64(lat[min(len(lat)-1, int(p*float64(len(lat))))].Microseconds()) / 1000
	}
	r.LatencyMs = map[string]float64{"p50": pct(0.50), "p90": pct(0.90), "p99": pct(0.99), "max": pct(1)}

	for i := 0; i < *runs; i++ {
		r.ParallelRuns = append(r.ParallelRuns, parallel(eng, files, *workers).Seconds())
	}
	r.ParallelSec = r.ParallelRuns[0]
	for _, s := range r.ParallelRuns {
		r.ParallelSec = min(r.ParallelSec, s)
	}
	r.LinesPerSecMT = float64(r.Lines) / r.ParallelSec

	fmt.Printf("corpus      %s\n", r.Corpus)
	fmt.Printf("files       %d (%d lines, %.1f MB), %d findings\n", r.Files, r.Lines, float64(r.Bytes)/1e6, r.Findings)
	fmt.Printf("latency     p50 %.2f ms  p90 %.2f ms  p99 %.2f ms  max %.2f ms\n", r.LatencyMs["p50"], r.LatencyMs["p90"], r.LatencyMs["p99"], r.LatencyMs["max"])
	fmt.Printf("serial      %.2f s  (%.0f lines/sec, 1 thread)\n", r.SerialSec, r.LinesPerSec)
	fmt.Printf("parallel    %.2f s best of %v with %d workers (%.0f lines/sec)\n", r.ParallelSec, r.ParallelRuns, r.Workers, r.LinesPerSecMT)
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(r, "", "  ")
		if err := os.WriteFile(*jsonOut, append(b, '\n'), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

func load(root string, maxSize int64) ([]file, error) {
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved // WalkDir does not descend into a symlinked root
	}
	var files []file
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		lang := engine.DetectLanguage(p)
		if !lang.Valid() {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxSize {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files = append(files, file{p, lang, src, bytes.Count(src, []byte{'\n'})})
		return nil
	})
	if err == nil && len(files) == 0 {
		err = fmt.Errorf("no supported files under %s", root)
	}
	return files, err
}

func parallel(eng *engine.Engine, files []file, workers int) time.Duration {
	jobs := make(chan *file)
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range jobs {
				_, _ = eng.Analyze(f.lang, f.src)
			}
		}()
	}
	for i := range files {
		jobs <- &files[i]
	}
	close(jobs)
	wg.Wait()
	return time.Since(start)
}
