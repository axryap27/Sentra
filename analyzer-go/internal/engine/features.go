package engine

import (
	"sort"
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

// Lowercased pattern tables, built once at init instead of on every call.
var (
	lowerUserInput    = lowerAll(userInputPatterns)
	lowerSanitization = lowerAll(sanitizationPatterns)
	lowerWeakCrypto   = lowerAll(weakCryptoPatterns)
	lowerFormatString = lowerAll(formatStringPatterns)
	lowerSecretIdents = lowerAll(secretIdentifierPatterns)
	funcIndex         = buildFuncIndex(dangerousFunctions)
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
	fv := FeatureVector{
		LanguageID:            lang.id(),
		DangerousFuncCategory: funcIndex.match(c.Name),
		ArgCount:              float64(c.ArgCount),
		HasStringConcatInArgs: b2f(c.HasStringConcatArg),
		IsInComment:           b2f(c.IsInComment),
		IsInTryCatch:          b2f(c.IsInTryCatch),
		IsInConditional:       b2f(c.IsInConditional),
		NodeDepth:             float64(c.NodeDepth),
		IsInLoop:              b2f(c.IsInLoop),
		IsPublicFunction:      b2f(c.IsPublicFunction),
	}

	combined := strings.ToLower(c.ArgSource + " " + c.RawLine)
	fv.HasUserInputSource = b2f(containsAnyLower(combined, lowerUserInput))
	fv.HasSanitizationNearby = b2f(containsAnyLower(strings.ToLower(c.RawLine), lowerSanitization))
	fv.HasFormatString = b2f(containsAnyLower(combined, lowerFormatString))
	fv.UsesWeakCrypto = b2f(containsAnyLower(combined, lowerWeakCrypto))
	fv.HasHardcodedSecret = detectHardcodedSecret(c)
	return fv
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// funcMatcher resolves a callee name to a CWE category.
type funcMatcher struct {
	exact       map[string]float64
	exactLower  map[string]float64
	lastSegment map[string]float64 // lowercased single-word patterns
	compound    []compoundPattern  // lowercased dotted patterns, longest first
}

type compoundPattern struct {
	lower string
	cat   float64
}

func buildFuncIndex(m map[string]float64) *funcMatcher {
	fm := &funcMatcher{
		exact:       m,
		exactLower:  make(map[string]float64, len(m)),
		lastSegment: make(map[string]float64, len(m)),
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic when lowercased patterns collide
	for _, k := range keys {
		lk := strings.ToLower(k)
		if _, dup := fm.exactLower[lk]; !dup {
			fm.exactLower[lk] = m[k]
		}
		if strings.Contains(k, ".") {
			fm.compound = append(fm.compound, compoundPattern{lk, m[k]})
		} else if _, dup := fm.lastSegment[lk]; !dup {
			fm.lastSegment[lk] = m[k]
		}
	}
	sort.SliceStable(fm.compound, func(i, j int) bool { return len(fm.compound[i].lower) > len(fm.compound[j].lower) })
	return fm
}

// match tries an exact match, then case-insensitive exact, then the last dotted
// segment against single-word patterns, then dotted patterns as substrings.
func (fm *funcMatcher) match(name string) float64 {
	if cat, ok := fm.exact[name]; ok {
		return cat
	}
	lower := strings.ToLower(name)
	if cat, ok := fm.exactLower[lower]; ok {
		return cat
	}
	last := lower
	if i := strings.LastIndexByte(lower, '.'); i >= 0 {
		last = lower[i+1:]
	}
	if cat, ok := fm.lastSegment[last]; ok {
		return cat
	}
	for _, p := range fm.compound {
		if strings.Contains(lower, p.lower) {
			return p.cat
		}
	}
	return CWENone
}

// detectHardcodedSecret checks if an assignment looks like a hardcoded secret.
func detectHardcodedSecret(c *Candidate) float64 {
	identifier := c.AssignedIdentifier
	if identifier == "" {
		identifier = c.Name
	}
	if !containsAnyLower(strings.ToLower(identifier), lowerSecretIdents) {
		return 0
	}

	value := c.AssignedValue
	if value == "" {
		value = c.RawLine
	}
	lowerVal := strings.ToLower(value)
	for _, src := range []string{"environ", "getenv", "input(", "config.", "os.", "env."} {
		if strings.Contains(lowerVal, src) {
			return 0
		}
	}
	for _, prefix := range secretPrefixes {
		if strings.Contains(value, prefix) {
			return 1
		}
	}
	if (strings.Contains(value, "\"") || strings.Contains(value, "'")) && len(value) > 10 {
		return 1
	}
	return 0
}

// containsAnyLower reports whether lowered text contains any lowered pattern.
func containsAnyLower(text string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(text, p) {
			return true
		}
	}
	return false
}
