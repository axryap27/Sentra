package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type SecurityIssue struct {
	Line     int    `json:"line"`
	Issue    string `json:"issue"`
	Severity string `json:"severity"`
}

type Language string

const (
	LanguagePython     Language = "python"
	LanguageJavaScript Language = "javascript"
	LanguageTypeScript Language = "typescript"
	LanguageJava       Language = "java"
	LanguageC          Language = "c"
	LanguageCPP        Language = "cpp"
	LanguageGo         Language = "go"
	LanguagePHP        Language = "php"
	LanguageCSharp     Language = "csharp"
	LanguageRust       Language = "rust"
	LanguageUnknown    Language = "unknown"
)

type Analyzer struct {
	fileSet  *token.FileSet
	issues   []SecurityIssue
	language Language
}

func NewAnalyzer(language Language) *Analyzer {
	return &Analyzer{
		fileSet:  token.NewFileSet(),
		issues:   make([]SecurityIssue, 0),
		language: language,
	}
}

func (a *Analyzer) addIssue(pos token.Pos, issue, severity string) {
	position := a.fileSet.Position(pos)
	a.issues = append(a.issues, SecurityIssue{
		Line:     position.Line,
		Issue:    issue,
		Severity: severity,
	})
}

func (a *Analyzer) analyzeFile(content string) error {
	// Use AI-powered analysis with language-specific patterns
	aiAnalyzer := NewAIAnalyzer(a.language)

	aiIssues, err := aiAnalyzer.AnalyzeWithAI(content)
	if err != nil {
		return fmt.Errorf("AI analysis failed: %v", err)
	}

	a.issues = aiIssues
	return nil
}

func (a *Analyzer) getIssues() []SecurityIssue {
	return a.issues
}

func main() {
	var filePath = flag.String("file", "", "File to analyze")
	var batchMode = flag.Bool("batch", false, "Batch mode: read file paths from stdin")
	var format = flag.String("format", "json", "Output format (json or text)")
	var workers = flag.Int("workers", 4, "Number of worker goroutines for batch processing")
	flag.Parse()

	if *batchMode {
		processBatch(*workers, *format)
	} else {
		if *filePath == "" {
			fmt.Fprintf(os.Stderr, "Error: --file parameter is required\n")
			os.Exit(1)
		}
		processSingleFile(*filePath, *format)
	}
}

func processSingleFile(filePath, format string) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Detect language from file path
	language := detectLanguage(filePath)

	analyzer := NewAnalyzer(language)
	err = analyzer.analyzeFile(string(content))
	if err != nil {
		log.Fatalf("Analysis error: %v", err)
	}

	issues := analyzer.getIssues()
	outputResults(issues, format)
}

type FileJob struct {
	Path     string
	Content  string
	Language Language
}

type FileResult struct {
	Path   string
	Issues []SecurityIssue
	Error  error
}

func processBatch(workers int, format string) {

	jobs := make(chan FileJob, workers*2)
	results := make(chan FileResult, workers*2)

	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				analyzer := NewAnalyzer(job.Language)
				err := analyzer.analyzeFile(job.Content)

				result := FileResult{
					Path:   job.Path,
					Issues: analyzer.getIssues(),
					Error:  err,
				}
				results <- result
			}
		}()
	}

	// Read file paths from stdin and send jobs
	go func() {
		defer close(jobs)
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			filePath := strings.TrimSpace(scanner.Text())
			if filePath == "" {
				continue
			}

			content, err := os.ReadFile(filePath)
			if err != nil {
				results <- FileResult{Path: filePath, Error: err}
				continue
			}

			language := detectLanguage(filePath)
			jobs <- FileJob{
				Path:     filePath,
				Content:  string(content),
				Language: language,
			}
		}
	}()

	// Close results channel when all workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and output results
	allResults := make(map[string][]SecurityIssue)
	for result := range results {
		if result.Error != nil {
			fmt.Fprintf(os.Stderr, "Error processing %s: %v\n", result.Path, result.Error)
			continue
		}
		allResults[result.Path] = result.Issues
	}

	if format == "json" {
		jsonOutput, err := json.MarshalIndent(allResults, "", "  ")
		if err != nil {
			log.Fatalf("Error marshaling JSON: %v", err)
		}
		fmt.Println(string(jsonOutput))
	} else {
		for path, issues := range allResults {
			fmt.Printf("\n=== %s ===\n", path)
			if len(issues) == 0 {
				fmt.Println("No security vulnerabilities found.")
			} else {
				for i, issue := range issues {
					fmt.Printf("%d. [Line %d] (%s) %s\n", i+1, issue.Line, issue.Severity, issue.Issue)
				}
			}
		}
	}
}

func outputResults(issues []SecurityIssue, format string) {
	if format == "json" {
		jsonOutput, err := json.MarshalIndent(issues, "", "  ")
		if err != nil {
			log.Fatalf("Error marshaling JSON: %v", err)
		}
		fmt.Println(string(jsonOutput))
	} else {
		if len(issues) == 0 {
			fmt.Println("No security vulnerabilities found.")
		} else {
			for i, issue := range issues {
				fmt.Printf("%d. [Line %d] (%s) %s\n", i+1, issue.Line, issue.Severity, issue.Issue)
			}
		}
	}
}

// detectLanguage determines the programming language from file extension
func detectLanguage(filePath string) Language {
	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".py":
		return LanguagePython
	case ".js", ".jsx":
		return LanguageJavaScript
	case ".ts", ".tsx":
		return LanguageTypeScript
	case ".java":
		return LanguageJava
	case ".c":
		return LanguageC
	case ".cpp", ".cc", ".cxx", ".hpp", ".h":
		return LanguageCPP
	case ".go":
		return LanguageGo
	case ".php":
		return LanguagePHP
	case ".cs":
		return LanguageCSharp
	case ".rs":
		return LanguageRust
	default:
		return LanguageUnknown
	}
}
