package engine

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
)

// Version identifies the engine; the extension mixes it into its cache keys.
const Version = "0.3.0"

// Finding is one reported issue. Line/column are 1-based.
type Finding struct {
	Line       int     `json:"line"`
	Column     int     `json:"column"`
	EndLine    int     `json:"endLine"`
	EndColumn  int     `json:"endColumn"`
	Rule       string  `json:"rule"`
	CWE        string  `json:"cwe"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
	Symbol     string  `json:"symbol"`
	Issue      string  `json:"issue"`
}

// Engine analyzes source code. It is safe for concurrent use: the model is
// loaded once and tree-sitter parsers (which are not thread-safe) are pooled
// per language.
type Engine struct {
	clf     *RandomForestClassifier
	parsers map[Language]*sync.Pool
	kinds   map[Language][]nodeKind
}

var (
	defaultEngine     *Engine
	defaultEngineOnce sync.Once
)

// Default returns the process-wide engine, loading the embedded model on first use.
func Default() *Engine {
	defaultEngineOnce.Do(func() {
		clf, _ := GetClassifier() // nil classifier falls back to heuristic confidence
		e := &Engine{clf: clf, parsers: make(map[Language]*sync.Pool, len(grammars)), kinds: make(map[Language][]nodeKind)}
		for lang, grammar := range grammars {
			g := grammar
			e.kinds[lang] = kindTable(g)
			e.parsers[lang] = &sync.Pool{New: func() any {
				p := sitter.NewParser()
				p.SetLanguage(g)
				return p
			}}
		}
		defaultEngine = e
	})
	return defaultEngine
}

// Analyze scans src written in lang and returns findings sorted by position.
func (e *Engine) Analyze(lang Language, src []byte) ([]Finding, error) {
	pool, ok := e.parsers[lang]
	if !ok {
		return nil, fmt.Errorf("unsupported language %q", lang)
	}
	p := pool.Get().(*sitter.Parser)
	candidates := parseCandidates(p, lang, e.kinds[lang], src)
	pool.Put(p)

	if len(candidates) == 0 {
		return fallbackLineScan(src), nil
	}

	findings := make([]Finding, 0, 8)
	for i := range candidates {
		c := &candidates[i]
		fv := ExtractFeatures(c, lang)
		if fv.IsInComment == 1 {
			continue
		}
		category := fv.DangerousFuncCategory
		if fv.HasHardcodedSecret == 1 && category == CWENone {
			category = CWEHardcoded
		}
		if category == CWENone {
			continue
		}
		rule := rulesByCategory[category]
		if shouldFilter(rule.Name, &fv) {
			continue
		}
		confidence := e.confidence(&fv)
		findings = append(findings, Finding{
			Line:       c.Line,
			Column:     c.Column,
			EndLine:    c.EndLine,
			EndColumn:  c.EndColumn,
			Rule:       rule.Name,
			CWE:        rule.CWE,
			Severity:   severity(rule, &fv),
			Confidence: confidence,
			Symbol:     c.Name,
			Issue:      describe(rule, c.Name, confidence),
		})
	}
	return dedupe(findings), nil
}

// shouldFilter drops candidates whose context makes them false positives.
func shouldFilter(rule string, fv *FeatureVector) bool {
	switch rule {
	case "path_traversal":
		return fv.HasUserInputSource == 0 || fv.HasSanitizationNearby == 1
	case "sql_injection":
		return fv.HasStringConcatInArgs == 0 && fv.HasFormatString == 0
	}
	return false
}

func (e *Engine) confidence(fv *FeatureVector) float64 {
	if e.clf == nil {
		conf := 0.7
		if fv.HasUserInputSource == 1 {
			conf += 0.1
		}
		if fv.HasStringConcatInArgs == 1 {
			conf += 0.1
		}
		if fv.HasSanitizationNearby == 1 {
			conf -= 0.2
		}
		if fv.IsInTryCatch == 1 {
			conf -= 0.05
		}
		return clamp(conf, 0.3, 1)
	}
	pred := e.clf.Predict(fv.ToSlice())
	if pred.ClassIndex == 0 {
		return 0.3
	}
	return pred.Confidence
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func severity(r Rule, fv *FeatureVector) string {
	if fv.HasSanitizationNearby == 1 && r.Severity == "High" {
		return "Medium"
	}
	return r.Severity
}

func describe(r Rule, symbol string, confidence float64) string {
	msg := r.Message
	if symbol != "" {
		if len(symbol) > 60 {
			symbol = symbol[:57] + "..."
		}
		msg = fmt.Sprintf("%s [%s]", msg, symbol)
	}
	switch {
	case confidence > 0.8:
		return msg + " (High confidence)"
	case confidence > 0.6:
		return msg + " (Medium confidence)"
	default:
		return msg + " (Low confidence)"
	}
}

// fallbackLineScan is used when tree-sitter yields no candidates.
func fallbackLineScan(src []byte) []Finding {
	var findings []Finding
	for i, line := range strings.Split(string(src), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		for _, name := range sortedDangerousNames {
			if !strings.Contains(trimmed, name+"(") && !strings.Contains(trimmed, name+" ") {
				continue
			}
			rule := rulesByCategory[dangerousFunctions[name]]
			findings = append(findings, Finding{
				Line: i + 1, Column: 1, EndLine: i + 1, EndColumn: len(line) + 1,
				Rule: rule.Name, CWE: rule.CWE, Severity: rule.Severity, Confidence: 0.3,
				Symbol: name, Issue: rule.Message + " [" + name + "]",
			})
			break // one finding per line in fallback mode
		}
	}
	return findings
}

var sortedDangerousNames = func() []string {
	names := make([]string, 0, len(dangerousFunctions))
	for n := range dangerousFunctions {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}()

// dedupe keeps the first finding per (line, severity).
func dedupe(findings []Finding) []Finding {
	type key struct {
		line int
		sev  string
	}
	seen := make(map[key]bool, len(findings))
	out := findings[:0]
	for _, f := range findings {
		k := key{f.Line, f.Severity}
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}
