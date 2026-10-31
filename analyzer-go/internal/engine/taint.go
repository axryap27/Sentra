package engine

import (
	"regexp"
	"strings"
)

// Light intra-procedural dataflow. While walking a function body in source order
// the walker records, for each local variable, where its value came from. A sink's
// arguments are then described by the union of the facts of the variables they
// mention. This is deliberately simple: one pass, no control flow (both branches
// of an if or ternary count), no inter-procedural flow, no aliasing. It is enough
// to tell `query("SELECT ... " + userInput)` from `query(CONSTANT)`.

// taint is a set of facts about a value.
type taint uint8

const (
	tInput    taint = 1 << iota // reaches back to a user-input source (request.*, input(), argv, ...)
	tParam                      // reaches back to a parameter of the enclosing function
	tConcat                     // built by concatenation, formatting or appending
	tWeakAlgo                   // contains a weak algorithm name literal ("MD5", "DES", ...)
)

// valueInfo describes an expression or a variable's current value.
type valueInfo struct {
	flags    taint
	constant bool // only literals and constant variables
	depth    int  // variables only: branch depth (if/loop/try nesting) where it was defined
}

// frame is the variable environment of one function.
type frame map[string]valueInfo

// neutralIdents are identifiers that neither carry taint nor make an expression non-constant.
var neutralIdents = map[string]bool{
	"true": true, "false": true, "null": true, "nil": true, "None": true, "True": true,
	"False": true, "undefined": true, "new": true, "typeof": true, "instanceof": true,
	"and": true, "or": true, "not": true, "in": true, "is": true,
}

// receiverIdents are never treated as tainted parameters (every method has one).
var receiverIdents = map[string]bool{"self": true, "cls": true, "this": true}

// mutators are methods that fold their arguments into the receiver.
var mutators = map[string]bool{
	"add": true, "addAll": true, "append": true, "extend": true, "insert": true, "push": true,
	"put": true, "putAll": true, "concat": true, "write": true, "unshift": true, "update": true,
}

var weakAlgoRE = regexp.MustCompile(`(?i)(^|[^a-z0-9])(md2|md4|md5|sha-?1|des|desede|3des|tripledes|rc2|rc4|arcfour|blowfish)([^a-z0-9]|$)|/ecb/`)

var sanitizerPatterns = lowerAll([]string{
	"escape", "sanitize", "htmlspecialchars", "encodefor", "encodeuricomponent", "quote(",
	"safe_join", "secure_filename", "strip_tags", "bleach.clean", "normalize(",
	"filenameutils.getname", "basename(",
})

// lookup finds a variable in the innermost frame that defines it.
func (w *walker) lookup(name string) (valueInfo, bool) {
	for i := len(w.frames) - 1; i >= 0; i-- {
		if v, ok := w.frames[i][name]; ok {
			return v, true
		}
	}
	return valueInfo{}, false
}

// assign records a new value. An assignment nested in more branches than the
// variable's definition may not execute, so it is merged with the old value
// (a weak update): `if (p == null) p = "";` must not erase p's taint.
func (w *walker) assign(name string, v valueInfo) {
	if name == "" || len(w.frames) == 0 || receiverIdents[name] {
		return
	}
	v.depth = w.sc.branchDepth
	if old, ok := w.lookup(name); ok && w.sc.branchDepth > old.depth {
		v = valueInfo{flags: old.flags | v.flags, constant: old.constant && v.constant, depth: old.depth}
	}
	w.frames[len(w.frames)-1][name] = v
}

// pushFrame starts a function scope; every identifier in params is a parameter.
func (w *walker) pushFrame(params string) {
	f := frame{}
	for _, id := range identifiers(params) {
		if !receiverIdents[id.name] {
			f[id.name] = valueInfo{flags: tParam}
		}
	}
	w.frames = append(w.frames, f)
}

// analyzeExpr summarizes an expression's source text.
func (w *walker) analyzeExpr(text string) valueInfo {
	v := valueInfo{constant: true}
	lower := strings.ToLower(text)
	if containsAnyLower(lower, lowerUserInput) {
		v.flags |= tInput
		v.constant = false
	}
	if containsConcatPattern(text) || strings.Contains(text, ".format(") || strings.Contains(text, ".append(") ||
		strings.Contains(lower, "string.format(") || strings.Contains(lower, "sprintf(") || hasPercentFormat(text) {
		v.flags |= tConcat
	}
	for _, id := range identifiers(text) {
		if id.literal {
			if weakAlgoRE.MatchString(id.name) {
				v.flags |= tWeakAlgo
			}
			continue
		}
		if neutralIdents[id.name] || id.kwarg {
			continue
		}
		if id.member {
			v.constant = false // field access / method call: value unknown
			continue
		}
		if known, ok := w.lookup(id.name); ok {
			v.flags |= known.flags
			v.constant = v.constant && known.constant
		} else {
			v.constant = false
		}
	}
	if containsAnyLower(lower, sanitizerPatterns) {
		v.flags &^= tInput | tParam
	}
	return v
}

// hasPercentFormat detects Python-style "..." % x formatting.
func hasPercentFormat(text string) bool {
	i := strings.Index(text, "%")
	for i >= 0 {
		rest := strings.TrimLeft(text[i+1:], " ")
		before := strings.TrimRight(text[:i], " ")
		if len(before) > 0 && (before[len(before)-1] == '"' || before[len(before)-1] == '\'') && len(rest) > 0 && rest[0] != '=' {
			return true
		}
		j := strings.Index(text[i+1:], "%")
		if j < 0 {
			break
		}
		i += j + 1
	}
	return false
}

// ident is one token from identifiers().
type ident struct {
	name    string
	literal bool // contents of a string literal
	member  bool // preceded by '.', '->' or '::' (a field or method, not a variable)
	kwarg   bool // followed by a single '=' (a keyword-argument name)
}

// identifiers tokenizes source text into identifiers and string literal contents.
// Interpolations inside f-strings and template literals are tokenized too.
func identifiers(text string) []ident {
	var out []ident
	n := len(text)
	for i := 0; i < n; {
		c := text[i]
		switch {
		case c == '"' || c == '\'' || c == '`':
			fstring := c != '`' && i > 0 && (text[i-1] == 'f' || text[i-1] == 'F')
			j := i + 1
			for j < n && text[j] != c {
				if text[j] == '\\' {
					j++
				}
				j++
			}
			body := text[i+1 : min(j, n)]
			out = append(out, ident{name: body, literal: true})
			if c == '`' || fstring {
				for _, seg := range interpolations(body) {
					out = append(out, identifiers(seg)...)
				}
			}
			i = j + 1
		case isIdentStart(c):
			j := i + 1
			for j < n && isIdentPart(text[j]) {
				j++
			}
			tok := ident{name: text[i:j]}
			if j < n && (text[j] == '"' || text[j] == '\'') && (tok.name == "f" || tok.name == "F" ||
				tok.name == "r" || tok.name == "b" || tok.name == "u" || tok.name == "rb" || tok.name == "br") {
				i = j // string prefix, not an identifier
				continue
			}
			p := i - 1
			for p >= 0 && text[p] == ' ' {
				p--
			}
			if p >= 0 && (text[p] == '.' || (text[p] == '>' && p > 0 && text[p-1] == '-') || (text[p] == ':' && p > 0 && text[p-1] == ':')) {
				tok.member = true
			}
			q := j
			for q < n && text[q] == ' ' {
				q++
			}
			if q < n && text[q] == '=' && (q+1 >= n || text[q+1] != '=') {
				tok.kwarg = true
			}
			out = append(out, tok)
			i = j
		case c >= '0' && c <= '9':
			for i < n && isIdentPart(text[i]) {
				i++
			}
		default:
			i++
		}
	}
	return out
}

// interpolations returns the expressions inside {...} or ${...} in a string body.
func interpolations(body string) []string {
	var segs []string
	for i := 0; i < len(body); i++ {
		if body[i] != '{' {
			continue
		}
		depth := 1
		j := i + 1
		for j < len(body) && depth > 0 {
			switch body[j] {
			case '{':
				depth++
			case '}':
				depth--
			}
			j++
		}
		if depth == 0 && j-1 > i+1 {
			segs = append(segs, body[i+1:j-1])
		}
		i = j - 1
	}
	return segs
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

// assignedNames splits an assignment target into variable names: "a, b" -> [a b].
// Targets like obj.field or arr[i] return nil (not a local variable).
func assignedNames(target string) []string {
	var names []string
	for _, part := range strings.Split(target, ",") {
		part = strings.TrimSpace(strings.Trim(strings.TrimSpace(part), "()[]"))
		if fields := strings.Fields(part); len(fields) > 0 {
			part = fields[len(fields)-1] // "String x" / "var x" / "let mut x"
		}
		part = strings.TrimLeft(part, "*&")
		if part == "" || !isIdentStart(part[0]) {
			continue
		}
		ok := true
		for i := 1; i < len(part); i++ {
			if !isIdentPart(part[i]) {
				ok = false
				break
			}
		}
		if ok {
			names = append(names, part)
		}
	}
	return names
}
