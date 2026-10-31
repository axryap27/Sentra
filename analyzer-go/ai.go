package main

import (
	"fmt"
	"strings"
)

// AIAnalyzer performs security analysis using tree-sitter AST parsing
// and a trained random forest classifier.
type AIAnalyzer struct {
	language   Language
	parser     *ASTParser
	classifier *RandomForestClassifier
}

// CWE descriptions map class names to human-readable issue descriptions.
var cweDescriptions = map[string]string{
	"code_injection":         "Code injection vulnerability: executes arbitrary code",
	"xss":                    "XSS vulnerability: user-controlled content rendered without escaping",
	"buffer_overflow":        "Buffer overflow vulnerability: unsafe memory operation without bounds checking",
	"weak_crypto":            "Cryptographic weakness: broken or deprecated algorithm",
	"unsafe_deserialization": "Unsafe deserialization: can execute arbitrary code from untrusted data",
	"hardcoded_secret":       "Hardcoded secret detected: potential credential leak",
	"command_injection":      "Command injection vulnerability: executes shell commands",
	"path_traversal":         "Path traversal vulnerability: user-controlled file access",
	"memory_leak":            "Memory management risk: potential memory leak or unsafe operation",
	"weak_randomness":        "Weak randomness: not cryptographically secure",
	"sql_injection":          "SQL injection vulnerability: dynamic query construction detected",
}

func NewAIAnalyzer(language Language) *AIAnalyzer {
	clf, _ := GetClassifier()
	return &AIAnalyzer{
		language:   language,
		parser:     NewASTParser(language),
		classifier: clf,
	}
}

// AnalyzeWithAI performs ML-powered security analysis:
// 1. Parse source into AST via tree-sitter
// 2. Extract candidate nodes (function calls, assignments, keyword args)
// 3. Compute feature vectors
// 4. Use features for CWE categorization + model for filtering/confidence
// 5. Map predictions back to SecurityIssue structs
func (ai *AIAnalyzer) AnalyzeWithAI(content string) ([]SecurityIssue, error) {
	sourceBytes := []byte(content)

	// Step 1-2: Parse AST and extract candidate nodes
	candidates := ai.parser.Parse(sourceBytes)

	// If tree-sitter fails to produce candidates, fall back to line scanning
	if len(candidates) == 0 {
		return ai.fallbackLineScan(content), nil
	}

	var issues []SecurityIssue

	for _, candidate := range candidates {
		// Step 3: Extract features
		fv := ExtractFeatures(&candidate, ai.language)

		// Skip nodes inside comments (AST-aware, not just # prefix)
		if fv.IsInComment == 1.0 {
			continue
		}

		// Determine CWE category from features (deterministic, precise)
		featureCategory := fv.DangerousFuncCategory
		className := categoryToClassName(featureCategory)

		// Handle hardcoded secrets (detected via assignment, not function call)
		if fv.HasHardcodedSecret == 1.0 && featureCategory == CWENone {
			className = "hardcoded_secret"
			featureCategory = CWEHardcoded
		}

		// Skip candidates with no security relevance
		if featureCategory == CWENone {
			continue
		}

		// Context-aware filtering: skip false positives
		if ai.shouldFilter(className, &fv) {
			continue
		}

		// Step 4: Use ML classifier for confidence scoring
		confidence := ai.getConfidence(&fv)

		// Determine severity from the CWE category
		severity := ai.getSeverity(className, &fv)

		// Step 5: Build SecurityIssue
		description := ai.buildDescription(&candidate, className, confidence)
		issue := SecurityIssue{
			Line:     candidate.Line,
			Issue:    description,
			Severity: severity,
		}
		issues = append(issues, issue)
	}

	return ai.deduplicateIssues(issues), nil
}

// shouldFilter returns true if this candidate is a false positive based on context.
func (ai *AIAnalyzer) shouldFilter(className string, fv *FeatureVector) bool {
	// Path traversal: only flag if user input is present and no sanitization
	if className == "path_traversal" {
		if fv.HasUserInputSource == 0 || fv.HasSanitizationNearby == 1.0 {
			return true
		}
	}

	// SQL injection: only flag if string concatenation or format strings are used
	if className == "sql_injection" {
		if fv.HasStringConcatInArgs == 0 && fv.HasFormatString == 0 {
			return true
		}
	}

	// If sanitization is present, reduce severity but don't fully filter
	// (we handle this in getSeverity instead)

	return false
}

// getConfidence uses the ML classifier to get a confidence score.
func (ai *AIAnalyzer) getConfidence(fv *FeatureVector) float64 {
	if ai.classifier == nil {
		// No model: use heuristic confidence based on features
		conf := 0.7
		if fv.HasUserInputSource == 1.0 {
			conf += 0.1
		}
		if fv.HasStringConcatInArgs == 1.0 {
			conf += 0.1
		}
		if fv.HasSanitizationNearby == 1.0 {
			conf -= 0.2
		}
		if fv.IsInTryCatch == 1.0 {
			conf -= 0.05
		}
		if conf < 0.3 {
			conf = 0.3
		}
		if conf > 1.0 {
			conf = 1.0
		}
		return conf
	}

	features := fv.ToSlice()
	pred := ai.classifier.Predict(features)

	// If model says "safe", lower confidence significantly
	if pred.ClassName == "safe" || pred.ClassIndex == 0 {
		return 0.3
	}

	return pred.Confidence
}

// getSeverity determines severity from the CWE category and context.
func (ai *AIAnalyzer) getSeverity(className string, fv *FeatureVector) string {
	// Base severity from CWE type
	baseSeverity := "Medium"
	switch className {
	case "code_injection", "command_injection", "buffer_overflow",
		"unsafe_deserialization", "hardcoded_secret", "path_traversal",
		"sql_injection", "xss":
		baseSeverity = "High"
	case "weak_crypto", "memory_leak", "weak_randomness":
		baseSeverity = "Medium"
	}

	// Downgrade if sanitization is present
	if fv.HasSanitizationNearby == 1.0 && baseSeverity == "High" {
		return "Medium"
	}

	return baseSeverity
}

// buildDescription creates a human-readable description from the classification.
func (ai *AIAnalyzer) buildDescription(candidate *CandidateNode, className string, confidence float64) string {
	base := cweDescriptions[className]
	if base == "" {
		base = fmt.Sprintf("Security vulnerability detected: %s", className)
	}

	// Add the specific function/identifier name for context
	detail := base
	if candidate.Name != "" {
		funcName := candidate.Name
		if len(funcName) > 60 {
			funcName = funcName[:57] + "..."
		}
		detail = fmt.Sprintf("%s [%s]", base, funcName)
	}

	// Add confidence level
	if confidence > 0.8 {
		detail += " (High confidence)"
	} else if confidence > 0.6 {
		detail += " (Medium confidence)"
	} else {
		detail += " (Low confidence)"
	}

	return detail
}

// fallbackLineScan does simple line-by-line scanning when AST parsing fails.
func (ai *AIAnalyzer) fallbackLineScan(content string) []SecurityIssue {
	var issues []SecurityIssue
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		for funcName, category := range dangerousFunctions {
			if strings.Contains(trimmed, funcName+"(") || strings.Contains(trimmed, funcName+" ") {
				severity := "Medium"
				if category == CWECodeInject || category == CWECmdInject ||
					category == CWEBufferOvfl || category == CWEDeserial {
					severity = "High"
				}

				className := categoryToClassName(category)
				desc := cweDescriptions[className]
				if desc == "" {
					desc = "Security issue detected"
				}

				issues = append(issues, SecurityIssue{
					Line:     lineNum + 1,
					Issue:    desc + " [" + funcName + "]",
					Severity: severity,
				})
				break // one issue per line in fallback mode
			}
		}
	}

	return issues
}

// categoryToClassName maps numeric CWE category to class name.
func categoryToClassName(cat float64) string {
	switch cat {
	case CWECodeInject:
		return "code_injection"
	case CWEXSS:
		return "xss"
	case CWEBufferOvfl:
		return "buffer_overflow"
	case CWEWeakCrypto:
		return "weak_crypto"
	case CWEDeserial:
		return "unsafe_deserialization"
	case CWEHardcoded:
		return "hardcoded_secret"
	case CWECmdInject:
		return "command_injection"
	case CWEPathTraverse:
		return "path_traversal"
	case CWEMemLeak:
		return "memory_leak"
	case CWEWeakRand:
		return "weak_randomness"
	case CWESQLInject:
		return "sql_injection"
	default:
		return "safe"
	}
}

// deduplicateIssues removes duplicate issues on the same line with the same severity.
func (ai *AIAnalyzer) deduplicateIssues(issues []SecurityIssue) []SecurityIssue {
	seen := make(map[string]bool)
	var result []SecurityIssue

	for _, issue := range issues {
		key := fmt.Sprintf("%d:%s", issue.Line, issue.Severity)
		if !seen[key] {
			seen[key] = true
			result = append(result, issue)
		}
	}

	return result
}

// GetAnalysisReport generates a detailed analysis report.
func (ai *AIAnalyzer) GetAnalysisReport(issues []SecurityIssue) string {
	if len(issues) == 0 {
		return "ML Analysis: No security vulnerabilities detected. Code appears secure."
	}

	report := "ML Security Analysis Report (Tree-sitter AST + Random Forest)\n"
	report += "==============================================================\n"
	report += fmt.Sprintf("Total Issues Found: %d\n\n", len(issues))

	severityCount := make(map[string]int)
	for _, issue := range issues {
		severityCount[issue.Severity]++
	}

	for severity, count := range severityCount {
		report += fmt.Sprintf("%s Severity: %d issues\n", severity, count)
	}

	report += "\nDetailed Findings:\n"
	for i, issue := range issues {
		report += fmt.Sprintf("%d. Line %d [%s]: %s\n",
			i+1, issue.Line, issue.Severity, issue.Issue)
	}

	return report
}
