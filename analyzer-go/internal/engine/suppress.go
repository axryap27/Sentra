package engine

import (
	"bytes"
	"strings"
)

// Inline suppressions, in any comment syntax:
//
//	x = md5(data)  // sentra-ignore
//	x = md5(data)  # sentra-ignore: weak_crypto
//	// sentra-ignore: weak_crypto, sql_injection     (applies to the next line)
//	/* sentra-ignore-file */                          (anywhere: suppress the whole file)
//
// Without a rule list, every rule is suppressed on that line.
const (
	ignoreMarker     = "sentra-ignore"
	ignoreFileMarker = "sentra-ignore-file"
)

func applySuppressions(src []byte, findings []Finding) []Finding {
	if len(findings) == 0 || !bytes.Contains(src, []byte(ignoreMarker)) {
		return findings
	}
	if bytes.Contains(src, []byte(ignoreFileMarker)) {
		return findings[:0]
	}
	lines := bytes.Split(src, []byte{'\n'})
	out := findings[:0]
	for _, f := range findings {
		if !suppressed(lines, f.Line, f.Rule) {
			out = append(out, f)
		}
	}
	return out
}

// suppressed checks the finding's line and, if it is a comment-only line, the line above.
func suppressed(lines [][]byte, line int, rule string) bool {
	if line < 1 || line > len(lines) {
		return false
	}
	if rules, ok := ignoreDirective(string(lines[line-1])); ok && matchesRule(rules, rule) {
		return true
	}
	if line >= 2 {
		prev := strings.TrimSpace(string(lines[line-2]))
		if isCommentOnly(prev) {
			if rules, ok := ignoreDirective(prev); ok && matchesRule(rules, rule) {
				return true
			}
		}
	}
	return false
}

// ignoreDirective parses "sentra-ignore[: rule, rule]" from a line.
func ignoreDirective(line string) ([]string, bool) {
	i := strings.Index(line, ignoreMarker)
	if i < 0 {
		return nil, false
	}
	rest := strings.TrimSpace(line[i+len(ignoreMarker):])
	if !strings.HasPrefix(rest, ":") {
		return nil, true
	}
	rest = strings.TrimSpace(rest[1:])
	if end := strings.IndexAny(rest, "*/-#>"); end >= 0 { // trailing "*/", "-->"
		rest = rest[:end]
	}
	var rules []string
	for _, r := range strings.FieldsFunc(rest, func(c rune) bool { return c == ',' || c == ' ' || c == '\t' }) {
		rules = append(rules, r)
	}
	return rules, true
}

func matchesRule(rules []string, rule string) bool {
	if len(rules) == 0 {
		return true
	}
	for _, r := range rules {
		if r == rule {
			return true
		}
	}
	return false
}

func isCommentOnly(line string) bool {
	for _, p := range []string{"//", "#", "/*", "*", "--", "<!--"} {
		if strings.HasPrefix(line, p) {
			return true
		}
	}
	return false
}
