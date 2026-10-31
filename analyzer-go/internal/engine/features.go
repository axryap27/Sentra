package engine

import (
	"regexp"
	"strings"
	"unicode"
)

// FeatureVector holds the numeric features fed into the classifier. Field order
// is the index order of ToSlice() and must match training/generate_dataset.py and
// FeatureNames.
type FeatureVector struct {
	DangerousFuncCategory float64 // 0: sink category (CWE* constant)
	ArgCount              float64 // 1
	HasStringConcatInArgs float64 // 2
	HasUserInputSource    float64 // 3: user-input pattern on the same line
	IsInComment           float64 // 4
	IsInTryCatch          float64 // 5
	IsInConditional       float64 // 6
	HasSanitizationNearby float64 // 7
	NodeDepth             float64 // 8
	IsInLoop              float64 // 9
	HasFormatString       float64 // 10
	IsPublicFunction      float64 // 11
	UsesWeakCrypto        float64 // 12: weak algorithm name on the same line
	HasHardcodedSecret    float64 // 13
	LanguageID            float64 // 14
	ArgFromUserInput      float64 // 15: an argument traces to a user-input source (taint.go)
	ArgFromParam          float64 // 16: an argument traces to a function parameter
	ArgBuiltWithConcat    float64 // 17: an argument was built by concatenation/formatting
	ArgsConstant          float64 // 18: all arguments are literals or constant variables
	WeakAlgorithmArg      float64 // 19: an argument names a weak algorithm
}

// NumFeatures is the length of FeatureVector.ToSlice().
const NumFeatures = 20

// FeatureNames are the feature names in index order.
var FeatureNames = [NumFeatures]string{
	"dangerous_func_category", "arg_count", "has_string_concat_in_args", "has_user_input_source",
	"is_in_comment", "is_in_try_catch", "is_in_conditional", "has_sanitization_nearby",
	"node_depth", "is_in_loop", "has_format_string", "is_public_function", "uses_weak_crypto",
	"has_hardcoded_secret", "language_id", "arg_from_user_input", "arg_from_param",
	"arg_built_with_concat", "args_constant", "weak_algorithm_arg",
}

// ToSlice converts the feature vector to a slice for the classifier.
func (f *FeatureVector) ToSlice() []float64 {
	return []float64{
		f.DangerousFuncCategory, f.ArgCount, f.HasStringConcatInArgs, f.HasUserInputSource,
		f.IsInComment, f.IsInTryCatch, f.IsInConditional, f.HasSanitizationNearby,
		f.NodeDepth, f.IsInLoop, f.HasFormatString, f.IsPublicFunction, f.UsesWeakCrypto,
		f.HasHardcodedSecret, f.LanguageID, f.ArgFromUserInput, f.ArgFromParam,
		f.ArgBuiltWithConcat, f.ArgsConstant, f.WeakAlgorithmArg,
	}
}

// Sink categories (feature 0 values and class indices).
const (
	CWENone         = 0
	CWECodeInject   = 1  // CWE-94
	CWEXSS          = 2  // CWE-79
	CWEBufferOvfl   = 3  // CWE-120
	CWEWeakCrypto   = 4  // CWE-327
	CWEDeserial     = 5  // CWE-502
	CWEHardcoded    = 6  // CWE-798
	CWECmdInject    = 7  // CWE-78
	CWEPathTraverse = 8  // CWE-22
	CWEMemLeak      = 9  // CWE-401
	CWEWeakRand     = 10 // CWE-330
	CWESQLInject    = 11 // CWE-89
)

// userInputPatterns are expressions indicating user-supplied data.
var userInputPatterns = []string{
	"request.", "req.", "params[", "argv", "stdin",
	"input(", "raw_input(", "args.", "query.",
	"Request.", "GET[", "POST[", "COOKIE[", "$_REQUEST", "$_SERVER",
	"HttpServletRequest", "getParameter", "getHeader", "getCookies", "getQueryString",
	"getInputStream", "getReader(", "os.Args", "flag.", "r.URL", "r.Body", "r.Form",
	"user_input", "userinput",
}

// sanitizationPatterns indicate sanitization or escaping on the same line.
var sanitizationPatterns = []string{
	"escape(", "sanitize(", "htmlspecialchars(", "html.EscapeString(",
	"encodeURIComponent(", "quote(", "safe_join(", "secure_filename(",
	"prepared", "parameterized", "bindParam(", "Sanitize(",
	"validate(", "Validate(", "clean(", "strip_tags(", "encodeFor",
}

var weakCryptoPatterns = []string{"MD5", "SHA1", "SHA-1", "DES", "RC4"}

var formatStringPatterns = []string{
	"%s", "%d", "%x", "%v", "{}", "f\"", "f'", "format(", "Sprintf(", "printf(",
}

var (
	lowerUserInput    = lowerAll(userInputPatterns)
	lowerSanitization = lowerAll(sanitizationPatterns)
	lowerFormatString = lowerAll(formatStringPatterns)
	// Matched as whole words so "des" does not fire on "describe".
	weakCryptoWordRE = regexp.MustCompile(`(?i)\b(md5|sha-?1|des|rc4)\b`)
)

func lowerAll(ps []string) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = strings.ToLower(p)
	}
	return out
}

// ExtractFeatures converts a Candidate into a FeatureVector.
func ExtractFeatures(c *Candidate, lang Language) FeatureVector {
	return extractFeatures(c, lang, matchSink(c.Name, lang))
}

func extractFeatures(c *Candidate, lang Language, s *sink) FeatureVector {
	fv := FeatureVector{
		LanguageID:            lang.id(),
		ArgCount:              float64(c.ArgCount),
		HasStringConcatInArgs: b2f(c.HasStringConcatArg),
		IsInComment:           b2f(c.IsInComment),
		IsInTryCatch:          b2f(c.IsInTryCatch),
		IsInConditional:       b2f(c.IsInConditional),
		NodeDepth:             float64(c.NodeDepth),
		IsInLoop:              b2f(c.IsInLoop),
		IsPublicFunction:      b2f(c.IsPublicFunction),
		ArgFromUserInput:      b2f(c.Arg.flags&tInput != 0),
		ArgFromParam:          b2f(c.Arg.flags&tParam != 0),
		ArgBuiltWithConcat:    b2f(c.Arg.flags&tConcat != 0),
		ArgsConstant:          b2f(c.Arg.constant),
		WeakAlgorithmArg:      b2f(c.Arg.flags&tWeakAlgo != 0),
	}
	if s != nil {
		fv.DangerousFuncCategory = s.cat
	}
	combined := strings.ToLower(c.ArgSource + " " + c.RawLine)
	fv.HasUserInputSource = b2f(containsAnyLower(combined, lowerUserInput))
	fv.HasSanitizationNearby = b2f(containsAnyLower(strings.ToLower(c.RawLine), lowerSanitization))
	fv.HasFormatString = b2f(containsAnyLower(combined, lowerFormatString))
	fv.UsesWeakCrypto = b2f(weakCryptoWordRE.MatchString(combined))
	fv.HasHardcodedSecret = b2f(isHardcodedSecret(c))
	return fv
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func containsAnyLower(text string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(text, p) {
			return true
		}
	}
	return false
}

// --- Hardcoded secrets ---

// secretWords mark an identifier as holding a credential.
var secretWords = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "secret": true, "token": true,
	"apikey": true, "credential": true, "credentials": true, "privatekey": true,
	"accesskey": true, "secretkey": true, "authtoken": true, "passphrase": true,
}

// notSecretWords mean the identifier names something about a secret, not the secret.
var notSecretWords = map[string]bool{
	"url": true, "uri": true, "path": true, "file": true, "name": true, "field": true,
	"type": true, "label": true, "message": true, "msg": true, "prompt": true, "header": true,
	"length": true, "len": true, "min": true, "max": true, "count": true, "form": true,
	"page": true, "template": true, "view": true, "reset": true, "change": true,
	"validator": true, "help": true, "policy": true, "hint": true, "input": true,
	"placeholder": true, "format": true, "prefix": true, "suffix": true, "regex": true,
	"pattern": true, "mask": true, "class": true, "error": true, "title": true, "text": true,
	"generator": true, "hasher": true, "hashers": true, "expiry": true, "timeout": true,
	"param": true, "key_name": true, "env": true, "var": true, "endpoint": true,
}

var placeholderWords = []string{"example", "your", "dummy", "test", "fake", "placeholder", "changeme", "xxx", "redacted", "todo"}

// Formats that are secrets whatever the variable is called.
var secretFormatRE = regexp.MustCompile(`AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20}|-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)

// isHardcodedSecret reports a string literal assigned to a credential-named
// variable, or a literal in a known credential format.
func isHardcodedSecret(c *Candidate) bool {
	if c.AssignedIdentifier == "" || !c.ValueIsLiteral {
		return false
	}
	value := strings.Trim(strings.TrimSpace(c.AssignedValue), "\"'`bru")
	if secretFormatRE.MatchString(value) {
		return true
	}
	words := identWords(c.AssignedIdentifier)
	secret := false
	for i, w := range words {
		if notSecretWords[w] {
			return false
		}
		if secretWords[w] || (i > 0 && secretWords[words[i-1]+w]) {
			secret = true
		}
	}
	if !secret || len(value) < 8 || strings.ContainsAny(value, " \t<>{}%$") {
		return false
	}
	lv := strings.ToLower(value)
	for _, p := range placeholderWords {
		if strings.Contains(lv, p) {
			return false
		}
	}
	return true
}

// identWords splits an identifier into lowercase words: "dbPassword" -> [db password],
// "API_KEY" -> [api key], "self.secret_key" -> [secret key] (last segment only).
func identWords(ident string) []string {
	if i := strings.LastIndexAny(ident, ".>:"); i >= 0 {
		ident = ident[i+1:]
	}
	var words []string
	var cur []rune
	prevLower := false
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for _, r := range ident {
		switch {
		case r == '_' || r == '-' || r == '$':
			flush()
			prevLower = false
		case unicode.IsUpper(r) && prevLower:
			flush()
			cur = append(cur, r)
			prevLower = false
		default:
			cur = append(cur, r)
			prevLower = unicode.IsLower(r) || unicode.IsDigit(r)
		}
	}
	flush()
	return words
}
