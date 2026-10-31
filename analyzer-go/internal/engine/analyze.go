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

// Options configure an Engine.
type Options struct {
	// DisableModel reports every candidate that passes the deterministic gates,
	// ignoring the classifier's thresholds (used for ablations in sentra-eval).
	DisableModel bool
}

// Engine analyzes source code. It is safe for concurrent use: the model is
// loaded once and tree-sitter parsers (which are not thread-safe) are pooled
// per language.
type Engine struct {
	opts    Options
	clf     *RandomForestClassifier
	parsers map[Language]*sync.Pool
	kinds   map[Language][]nodeKind
}

var (
	defaultEngine     *Engine
	defaultEngineOnce sync.Once
)

// Default returns the process-wide engine with default options.
func Default() *Engine {
	defaultEngineOnce.Do(func() {
		e, err := New(Options{})
		if err != nil {
			panic(err) // the embedded model is validated by tests; this is a build error
		}
		defaultEngine = e
	})
	return defaultEngine
}

// ModelError reports why the embedded model failed to load (nil if it loaded).
// Without a model the engine still works, using the deterministic gates alone.
func ModelError() error {
	_, err := GetClassifier()
	return err
}

// New builds an engine, loading the embedded model.
func New(opts Options) (*Engine, error) {
	clf, _ := GetClassifier() // nil-safe; see ModelError
	e := &Engine{opts: opts, clf: clf, parsers: make(map[Language]*sync.Pool, len(grammars)), kinds: make(map[Language][]nodeKind)}
	for lang, grammar := range grammars {
		g := grammar
		e.kinds[lang] = kindTable(g)
		e.parsers[lang] = &sync.Pool{New: func() any {
			p := sitter.NewParser()
			p.SetLanguage(g)
			return p
		}}
	}
	return e, nil
}

// Scored is a candidate that passed the deterministic gates, with its features
// and the classifier's probability for its rule.
type Scored struct {
	Candidate
	Rule        Rule
	Features    []float64
	Probability float64
	Threshold   float64
	Sanitized   bool
}

// Kept reports whether the classifier accepts the candidate.
func (s *Scored) Kept() bool { return s.Probability >= s.Threshold }

// Score parses src and returns every candidate that matches a sink and passes
// the deterministic gates, scored by the classifier.
func (e *Engine) Score(lang Language, src []byte) ([]Scored, error) {
	pool, ok := e.parsers[lang]
	if !ok {
		return nil, fmt.Errorf("unsupported language %q", lang)
	}
	p := pool.Get().(*sitter.Parser)
	candidates := parseCandidates(p, lang, e.kinds[lang], src)
	pool.Put(p)

	// For the memory-management gate: which functions call free().
	freeIn := map[string]bool{}
	for i := range candidates {
		if candidates[i].Name == "free" {
			freeIn[candidates[i].ParentFunctionName] = true
		}
	}

	var out []Scored
	for i := range candidates {
		c := &candidates[i]
		if c.IsInComment {
			continue
		}
		s := matchSink(c.Name, lang)
		if s != nil && c.AssignedIdentifier != "" && s.cat != CWEXSS {
			s = nil // assigning to x.query is not calling a sink; only property sinks (innerHTML) apply
		}
		if s == nil && !c.ValueIsLiteral {
			continue // neither a sink nor a possible hardcoded secret: skip feature extraction
		}
		fv := extractFeatures(c, lang, s)
		var rule Rule
		switch {
		case s != nil:
			rule = rulesByCategory[s.cat]
		case fv.HasHardcodedSecret == 1:
			rule = rulesByCategory[CWEHardcoded]
			fv.DangerousFuncCategory = CWEHardcoded
		default:
			continue
		}
		if !passesGates(rule, s, c, &fv, freeIn) {
			continue
		}
		sc := Scored{Candidate: *c, Rule: rule, Features: fv.ToSlice(), Sanitized: fv.HasSanitizationNearby == 1}
		sc.Probability = e.clf.Proba(sc.Features, rule.Name)
		if !e.opts.DisableModel {
			sc.Threshold = e.clf.Threshold(lang, rule.Name)
		}
		out = append(out, sc)
	}
	return out, nil
}

// Analyze scans src written in lang and returns findings sorted by position.
func (e *Engine) Analyze(lang Language, src []byte) ([]Finding, error) {
	scored, err := e.Score(lang, src)
	if err != nil {
		return nil, err
	}
	findings := make([]Finding, 0, len(scored))
	for i := range scored {
		s := &scored[i]
		if !s.Kept() {
			continue
		}
		sev := s.Rule.Severity
		if s.Sanitized && sev == "High" {
			sev = "Medium"
		}
		findings = append(findings, Finding{
			Line: s.Line, Column: s.Column, EndLine: s.EndLine, EndColumn: s.EndColumn,
			Rule: s.Rule.Name, CWE: s.Rule.CWE, Severity: sev,
			Confidence: round3(s.Probability), Symbol: s.Name,
			Issue: describe(s.Rule, s.Name),
		})
	}
	findings = applySuppressions(src, findings)
	return dedupe(findings), nil
}

// passesGates applies deterministic, rule-specific precision checks. They encode
// facts the model cannot learn from features alone (and keep obviously safe code
// out of the training data).
func passesGates(r Rule, s *sink, c *Candidate, fv *FeatureVector, freeIn map[string]bool) bool {
	var flags sinkFlag
	if s != nil {
		flags = s.flags
	}
	if flags&stringArg != 0 && !c.FirstArgIsString {
		return false // setTimeout(fn, ms) is not code injection
	}
	if flags&needsWeakAlgo != 0 && fv.WeakAlgorithmArg == 0 {
		return false // MessageDigest.getInstance("SHA-256")
	}
	switch r.Name {
	case "sql_injection":
		// Only dynamically built queries; parameterized/constant SQL is fine.
		return fv.ArgBuiltWithConcat == 1 && fv.ArgsConstant == 0
	case "path_traversal":
		return (fv.ArgFromUserInput == 1 || fv.HasUserInputSource == 1) && fv.ArgsConstant == 0
	case "command_injection", "code_injection", "xss":
		return fv.ArgsConstant == 0 // os.system("clear"), eval("1+1"), innerHTML = "<b>hi</b>"
	case "unsafe_deserialization":
		// yaml.load(f, Loader=yaml.SafeLoader); pickle.loads(pickle.dumps(x)) round-trips
		return !strings.Contains(c.ArgSource, "SafeLoader") && !strings.Contains(c.ArgSource, "dumps(")
	case "memory_leak":
		return !freeIn[c.ParentFunctionName]
	}
	return true
}

func round3(v float64) float64 { return float64(int(v*1000+0.5)) / 1000 }

func describe(r Rule, symbol string) string {
	if symbol == "" {
		return r.Message
	}
	if len(symbol) > 60 {
		symbol = symbol[:57] + "..."
	}
	return fmt.Sprintf("%s [%s]", r.Message, symbol)
}

// dedupe keeps the first finding per (line, rule) and sorts by position.
func dedupe(findings []Finding) []Finding {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Column < findings[j].Column
	})
	type key struct {
		line int
		rule string
	}
	seen := make(map[key]bool, len(findings))
	out := findings[:0]
	for _, f := range findings {
		k := key{f.Line, f.Rule}
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}
