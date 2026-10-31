// Package sarif renders findings as SARIF 2.1.0 for GitHub code scanning.
package sarif

import (
	"path/filepath"
	"sort"
	"strings"

	"sentra-analyzer/internal/engine"
)

var levels = map[string]string{"High": "error", "Medium": "warning", "Low": "note"}
var securitySeverity = map[string]string{"High": "8.0", "Medium": "5.0", "Low": "2.0"}

// Log builds a SARIF log. Paths are made relative to base (forward slashes).
func Log(results map[string][]engine.Finding, base string) map[string]any {
	ruleIndex := map[string]int{}
	rules := make([]map[string]any, 0, len(engine.Rules))
	for i, r := range engine.Rules {
		ruleIndex[r.Name] = i
		rules = append(rules, map[string]any{
			"id":               r.Name,
			"name":             pascalCase(r.Name),
			"shortDescription": map[string]string{"text": r.Title},
			"fullDescription":  map[string]string{"text": r.Message},
			"helpUri":          r.HelpURL(),
			"properties":       map[string]any{"tags": []string{"security", "external/cwe/" + strings.ToLower(r.CWE)}, "precision": "medium"},
		})
	}

	paths := make([]string, 0, len(results))
	for p := range results {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	out := []map[string]any{}
	for _, p := range paths {
		rel := p
		if r, err := filepath.Rel(base, p); err == nil && !strings.HasPrefix(r, "..") {
			rel = r
		}
		rel = filepath.ToSlash(rel)
		for _, f := range results[p] {
			out = append(out, map[string]any{
				"ruleId":    f.Rule,
				"ruleIndex": ruleIndex[f.Rule],
				"level":     levels[f.Severity],
				"message":   map[string]string{"text": f.Issue},
				"locations": []any{map[string]any{"physicalLocation": map[string]any{
					"artifactLocation": map[string]string{"uri": rel, "uriBaseId": "%SRCROOT%"},
					"region": map[string]int{"startLine": f.Line, "startColumn": f.Column,
						"endLine": f.EndLine, "endColumn": f.EndColumn},
				}}},
				"properties": map[string]any{"security-severity": securitySeverity[f.Severity], "confidence": f.Confidence, "cwe": f.CWE},
			})
		}
	}
	return map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "Sentra", "version": engine.Version,
				"informationUri": "https://github.com/axryap27/sentra", "rules": rules,
			}},
			"results": out,
		}},
	}
}

// pascalCase turns "sql_injection" into "SqlInjection".
func pascalCase(s string) string {
	var b strings.Builder
	for _, part := range strings.Split(s, "_") {
		if part != "" {
			b.WriteString(strings.ToUpper(part[:1]) + part[1:])
		}
	}
	return b.String()
}
