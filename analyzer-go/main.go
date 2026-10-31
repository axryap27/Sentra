// Command sentra-analyzer scans source files for security vulnerabilities.
//
// Modes:
//
//	--file PATH            analyze one file from disk
//	--stdin --lang LANG    analyze source read from stdin
//	--batch                read file paths from stdin (one per line), analyze in parallel
//	--serve                long-lived daemon speaking newline-delimited JSON on stdio
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"

	"sentra-analyzer/internal/engine"
	"sentra-analyzer/internal/sarif"
	"sentra-analyzer/internal/server"
)

func main() {
	filePath := flag.String("file", "", "file to analyze (with --stdin: only a hint for language detection)")
	useStdin := flag.Bool("stdin", false, "read source from stdin")
	lang := flag.String("lang", "", "language of the source (python, javascript, ...); inferred from --file if empty")
	batch := flag.Bool("batch", false, "read file paths from stdin and analyze them in parallel")
	serve := flag.Bool("serve", false, "run as a daemon speaking newline-delimited JSON over stdio")
	format := flag.String("format", "json", "output format: json, text, or sarif")
	workers := flag.Int("workers", runtime.NumCPU(), "parallel workers for --batch and --serve")
	version := flag.Bool("version", false, "print the engine version")
	flag.Parse()

	var err error
	switch {
	case *version:
		fmt.Println(engine.Version)
	case *serve:
		err = server.New(engine.Default(), *workers).Serve(os.Stdin, os.Stdout)
	case *batch:
		err = runBatch(*workers, *format)
	case *useStdin:
		err = runStdin(*lang, *filePath, *format)
	case *filePath != "":
		err = runFile(*filePath, *format)
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sentra-analyzer:", err)
		os.Exit(1)
	}
}

func resolveLang(lang, path string) (engine.Language, error) {
	l := engine.Language(lang)
	if lang == "" {
		l = engine.DetectLanguage(path)
	}
	if !l.Valid() {
		return "", fmt.Errorf("unsupported language %q", string(l))
	}
	return l, nil
}

func runStdin(lang, pathHint, format string) error {
	l, err := resolveLang(lang, pathHint)
	if err != nil {
		return err
	}
	src, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}
	findings, err := engine.Default().Analyze(l, src)
	if err != nil {
		return err
	}
	return output(findings, format)
}

func runFile(path, format string) error {
	l, err := resolveLang("", path)
	if err != nil {
		return err
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	findings, err := engine.Default().Analyze(l, src)
	if err != nil {
		return err
	}
	return output(findings, format)
}

func runBatch(workers int, format string) error {
	paths := make(chan string, workers*2)
	type result struct {
		path     string
		findings []engine.Finding
	}
	results := make(chan result, workers*2)

	var wg sync.WaitGroup
	for i := 0; i < max(1, workers); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range paths {
				l := engine.DetectLanguage(p)
				src, err := os.ReadFile(p)
				if err == nil && !l.Valid() {
					err = fmt.Errorf("unsupported language")
				}
				var findings []engine.Finding
				if err == nil {
					findings, err = engine.Default().Analyze(l, src)
				}
				if err != nil {
					fmt.Fprintf(os.Stderr, "error processing %s: %v\n", p, err)
					continue
				}
				results <- result{p, nonNil(findings)}
			}
		}()
	}
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			if p := strings.TrimSpace(sc.Text()); p != "" {
				paths <- p
			}
		}
		close(paths)
		wg.Wait()
		close(results)
	}()

	all := make(map[string][]engine.Finding)
	for r := range results {
		all[r.path] = r.findings
	}
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(all)
	case "sarif":
		cwd, _ := os.Getwd()
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(sarif.Log(all, cwd))
	}
	for path, findings := range all {
		fmt.Printf("\n=== %s ===\n", path)
		printText(findings)
	}
	return nil
}

func output(findings []engine.Finding, format string) error {
	if format == "sarif" {
		return fmt.Errorf("--format sarif requires --batch")
	}
	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(nonNil(findings))
	}
	printText(findings)
	return nil
}

func printText(findings []engine.Finding) {
	if len(findings) == 0 {
		fmt.Println("No security vulnerabilities found.")
		return
	}
	for i, f := range findings {
		fmt.Printf("%d. [Line %d] (%s) %s\n", i+1, f.Line, f.Severity, f.Issue)
	}
}

func nonNil(f []engine.Finding) []engine.Finding {
	if f == nil {
		return []engine.Finding{}
	}
	return f
}
