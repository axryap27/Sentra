package main

import (
	"strings"
)

// FeatureVector holds the numeric features fed into the ML classifier.
// Each field maps to an index in the float64 slice returned by ToSlice().
type FeatureVector struct {
	DangerousFuncCategory float64 // 0: CWE category (0=none,1=injection,2=xss,3=overflow,4=crypto,5=deser,6=secrets,7=cmdinj,8=pathtraversal,9=memleak,10=weakrand)
	ArgCount              float64 // 1
	HasStringConcatInArgs float64 // 2: 1.0 or 0.0
	HasUserInputSource    float64 // 3
	IsInComment           float64 // 4
	IsInTryCatch          float64 // 5
	IsInConditional       float64 // 6
	HasSanitizationNearby float64 // 7
	NodeDepth             float64 // 8
	IsInLoop              float64 // 9
	HasFormatString       float64 // 10
	IsPublicFunction      float64 // 11
	UsesWeakCrypto        float64 // 12
	HasHardcodedSecret    float64 // 13
	LanguageID            float64 // 14
}

const NumFeatures = 15

// ToSlice converts the feature vector to a float64 slice for the classifier.
func (f *FeatureVector) ToSlice() []float64 {
	return []float64{
		f.DangerousFuncCategory,
		f.ArgCount,
		f.HasStringConcatInArgs,
		f.HasUserInputSource,
		f.IsInComment,
		f.IsInTryCatch,
		f.IsInConditional,
		f.HasSanitizationNearby,
		f.NodeDepth,
		f.IsInLoop,
		f.HasFormatString,
		f.IsPublicFunction,
		f.UsesWeakCrypto,
		f.HasHardcodedSecret,
		f.LanguageID,
	}
}

// CWE categories as numeric IDs.
const (
	CWENone         = 0
	CWECodeInject   = 1  // CWE-94/95: eval, exec, Function()
	CWEXSS          = 2  // CWE-79: innerHTML, document.write, dangerouslySetInnerHTML
	CWEBufferOvfl   = 3  // CWE-120/121: strcpy, gets, sprintf, memcpy
	CWEWeakCrypto   = 4  // CWE-327/328: MD5, SHA1, DES
	CWEDeserial     = 5  // CWE-502: pickle, yaml.load, ObjectInputStream
	CWEHardcoded    = 6  // CWE-798: hardcoded passwords/keys
	CWECmdInject    = 7  // CWE-78: system(), exec(), os.system
	CWEPathTraverse = 8  // CWE-22: open() with user input
	CWEMemLeak      = 9  // CWE-401: malloc without free
	CWEWeakRand     = 10 // CWE-330: Math.random, rand()
	CWESQLInject    = 11 // CWE-89: dynamic query building
)

// dangerousFunctions maps function name patterns to CWE categories.
var dangerousFunctions = map[string]float64{
	// Code injection (CWE-94/95)
	"eval":     CWECodeInject,
	"exec":     CWECodeInject,
	"Function": CWECodeInject,

	// XSS (CWE-79)
	"innerHTML":               CWEXSS,
	"dangerouslySetInnerHTML": CWEXSS,
	"document.write":          CWEXSS,

	// Buffer overflow (CWE-120)
	"strcpy":   CWEBufferOvfl,
	"strcat":   CWEBufferOvfl,
	"sprintf":  CWEBufferOvfl,
	"gets":     CWEBufferOvfl,
	"scanf":    CWEBufferOvfl,
	"memcpy":   CWEBufferOvfl,
	"vsprintf": CWEBufferOvfl,

	// Weak crypto (CWE-327)
	"md5":                       CWEWeakCrypto,
	"sha1":                      CWEWeakCrypto,
	"MessageDigest.getInstance": CWEWeakCrypto,

	// Unsafe deserialization (CWE-502)
	"pickle.load":       CWEDeserial,
	"pickle.loads":      CWEDeserial,
	"yaml.load":         CWEDeserial,
	"ObjectInputStream": CWEDeserial,
	"unserialize":       CWEDeserial,
	"Marshal.load":      CWEDeserial,

	// Command injection (CWE-78)
	"system":                    CWECmdInject,
	"popen":                     CWECmdInject,
	"os.system":                 CWECmdInject,
	"os.popen":                  CWECmdInject,
	"subprocess.call":           CWECmdInject,
	"subprocess.Popen":          CWECmdInject,
	"subprocess.run":            CWECmdInject,
	"Runtime.getRuntime().exec": CWECmdInject,
	"ProcessBuilder":            CWECmdInject,
	"child_process.exec":        CWECmdInject,

	// Memory management (CWE-401)
	"malloc":  CWEMemLeak,
	"calloc":  CWEMemLeak,
	"realloc": CWEMemLeak,
	"free":    CWEMemLeak,

	// Weak randomness (CWE-330)
	"Math.random":   CWEWeakRand,
	"random.random": CWEWeakRand,
	"rand":          CWEWeakRand,

	// SQL queries (CWE-89) – flagged only when concat detected
	"execute":      CWESQLInject,
	"executeQuery": CWESQLInject,
	"query":        CWESQLInject,

	// Path operations (CWE-22)
	"open": CWEPathTraverse,

	// Keyword-argument patterns
	"shell=True": CWECmdInject,

	// Timing-based code injection (JS)
	"setTimeout":  CWECodeInject,
	"setInterval": CWECodeInject,
}

// userInputPatterns are identifiers/expressions indicating user-supplied data.
var userInputPatterns = []string{
	"request.", "req.", "params[", "argv", "stdin",
	"input(", "raw_input(", "args.", "query.",
	"Request.", "GET[", "POST[", "COOKIE[",
	"HttpServletRequest", "getParameter(",
	"os.Args", "flag.", "r.URL", "r.Body",
	"user_input", "userinput",
}

// sanitizationPatterns indicate the presence of sanitization/escaping.
var sanitizationPatterns = []string{
	"escape(", "sanitize(", "htmlspecialchars(", "html.EscapeString(",
	"encodeURIComponent(", "quote(", "safe_join(", "secure_filename(",
	"prepared", "parameterized", "bindParam(", "Sanitize(",
	"validate(", "Validate(", "clean(", "strip_tags(",
}

// weakCryptoPatterns indicate broken/weak cryptographic algorithms.
var weakCryptoPatterns = []string{
	"MD5", "md5", "SHA1", "sha1", "DES", "des", "RC4", "rc4",
	"SHA-1",
}

// formatStringPatterns indicate format string usage.
var formatStringPatterns = []string{
	"%s", "%d", "%x", "%v", "{}", "f\"", "f'",
	"format(", "Sprintf(", "printf(",
}

// secretIdentifierPatterns are variable names that suggest secrets.
var secretIdentifierPatterns = []string{
	"password", "passwd", "pwd", "secret", "api_key", "apikey",
	"access_key", "secret_key", "private_key", "auth_token",
	"token", "credential", "db_pass", "database_password",
}

// secretPrefixes indicate known API key / token formats.
var secretPrefixes = []string{
	"sk-", "pk-", "AIza", "AKIA", "ghp_", "gho_", "glpat-",
	"xoxb-", "xoxp-", "Bearer ", "Basic ",
}

// languageToID maps Language to a numeric ID for the feature vector.
func languageToID(lang Language) float64 {
	switch lang {
	case LanguagePython:
		return 0
	case LanguageJavaScript:
		return 1
	case LanguageTypeScript:
		return 2
	case LanguageJava:
		return 3
	case LanguageC:
		return 4
	case LanguageCPP:
		return 5
	case LanguageGo:
		return 6
	case LanguagePHP:
		return 7
	case LanguageCSharp:
		return 8
	case LanguageRust:
		return 9
	default:
		return -1
	}
}

// ExtractFeatures converts a CandidateNode into a FeatureVector.
func ExtractFeatures(c *CandidateNode, lang Language) FeatureVector {
	fv := FeatureVector{
		LanguageID: languageToID(lang),
	}

	// --- Feature 0: Dangerous function category ---
	fv.DangerousFuncCategory = matchDangerousFunction(c.Name)

	// --- Feature 1: Argument count ---
	fv.ArgCount = float64(c.ArgCount)

	// --- Feature 2: String concatenation in arguments ---
	if c.HasStringConcatArg {
		fv.HasStringConcatInArgs = 1.0
	}

	// --- Feature 3: User input source ---
	combined := c.ArgSource + " " + c.RawLine
	if containsAny(combined, userInputPatterns) {
		fv.HasUserInputSource = 1.0
	}

	// --- Feature 4: In comment ---
	if c.IsInComment {
		fv.IsInComment = 1.0
	}

	// --- Feature 5: In try/catch ---
	if c.IsInTryCatch {
		fv.IsInTryCatch = 1.0
	}

	// --- Feature 6: In conditional ---
	if c.IsInConditional {
		fv.IsInConditional = 1.0
	}

	// --- Feature 7: Sanitization nearby ---
	if containsAny(c.RawLine, sanitizationPatterns) {
		fv.HasSanitizationNearby = 1.0
	}

	// --- Feature 8: Node depth ---
	fv.NodeDepth = float64(c.NodeDepth)

	// --- Feature 9: In loop ---
	if c.IsInLoop {
		fv.IsInLoop = 1.0
	}

	// --- Feature 10: Format string ---
	if containsAny(combined, formatStringPatterns) {
		fv.HasFormatString = 1.0
	}

	// --- Feature 11: Public function ---
	if c.IsPublicFunction {
		fv.IsPublicFunction = 1.0
	}

	// --- Feature 12: Weak crypto ---
	if containsAny(combined, weakCryptoPatterns) {
		fv.UsesWeakCrypto = 1.0
	}

	// --- Feature 13: Hardcoded secret ---
	fv.HasHardcodedSecret = detectHardcodedSecret(c)

	return fv
}

// matchDangerousFunction finds the CWE category for a function name.
// Uses exact match, then last-segment match, then compound substring match.
func matchDangerousFunction(name string) float64 {
	// Exact match (highest priority)
	if cat, ok := dangerousFunctions[name]; ok {
		return cat
	}

	lower := strings.ToLower(name)

	// Try exact match case-insensitive
	for pattern, cat := range dangerousFunctions {
		if lower == strings.ToLower(pattern) {
			return cat
		}
	}

	// Extract the last segment after the last dot (e.g., "os.system" → "system")
	lastSegment := name
	if idx := strings.LastIndex(name, "."); idx >= 0 {
		lastSegment = name[idx+1:]
	}
	lastSegmentLower := strings.ToLower(lastSegment)

	// Match last segment against single-word patterns only
	for pattern, cat := range dangerousFunctions {
		if !strings.Contains(pattern, ".") && strings.ToLower(pattern) == lastSegmentLower {
			return cat
		}
	}

	// Match full name against compound patterns (containing dots)
	for pattern, cat := range dangerousFunctions {
		if strings.Contains(pattern, ".") && strings.Contains(lower, strings.ToLower(pattern)) {
			return cat
		}
	}

	return CWENone
}

// detectHardcodedSecret checks if an assignment looks like a hardcoded secret.
func detectHardcodedSecret(c *CandidateNode) float64 {
	// Check if the identifier name suggests a secret
	identifier := strings.ToLower(c.AssignedIdentifier)
	if identifier == "" {
		identifier = strings.ToLower(c.Name)
	}

	isSecretName := false
	for _, pattern := range secretIdentifierPatterns {
		if strings.Contains(identifier, pattern) {
			isSecretName = true
			break
		}
	}

	if !isSecretName {
		return 0.0
	}

	// Check if value looks hardcoded (string literal, long enough)
	value := c.AssignedValue
	if value == "" {
		value = c.RawLine
	}

	// Skip if value comes from environment or input
	lowerVal := strings.ToLower(value)
	if strings.Contains(lowerVal, "environ") || strings.Contains(lowerVal, "getenv") ||
		strings.Contains(lowerVal, "input(") || strings.Contains(lowerVal, "config.") ||
		strings.Contains(lowerVal, "os.") || strings.Contains(lowerVal, "env.") {
		return 0.0
	}

	// If value contains a known secret prefix, strong signal
	for _, prefix := range secretPrefixes {
		if strings.Contains(value, prefix) {
			return 1.0
		}
	}

	// If a secret-named variable is assigned a string literal of decent length
	if (strings.Contains(value, "\"") || strings.Contains(value, "'")) && len(value) > 10 {
		return 1.0
	}

	return 0.0
}

// containsAny checks if text contains any of the given patterns (case-insensitive).
func containsAny(text string, patterns []string) bool {
	lower := strings.ToLower(text)
	for _, p := range patterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}
