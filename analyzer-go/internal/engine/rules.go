package engine

// Rule describes one vulnerability class the engine reports.
type Rule struct {
	Name     string  // stable rule ID, used in suppressions and SARIF
	Category float64 // feature value (CWE* constant)
	CWE      string
	Severity string
	Title    string // short name, for SARIF and hovers
	Message  string // diagnostic text
}

// HelpURL links to the CWE entry for the rule.
func (r Rule) HelpURL() string {
	if len(r.CWE) > 4 {
		return "https://cwe.mitre.org/data/definitions/" + r.CWE[4:] + ".html"
	}
	return ""
}

// Rules lists every reportable rule.
var Rules = []Rule{
	{"code_injection", CWECodeInject, "CWE-94", "High", "Code injection", "Code injection vulnerability: executes arbitrary code"},
	{"xss", CWEXSS, "CWE-79", "High", "Cross-site scripting", "XSS vulnerability: user-controlled content rendered without escaping"},
	{"buffer_overflow", CWEBufferOvfl, "CWE-120", "High", "Buffer overflow", "Buffer overflow vulnerability: unsafe memory operation without bounds checking"},
	{"weak_crypto", CWEWeakCrypto, "CWE-327", "Medium", "Weak cryptography", "Cryptographic weakness: broken or deprecated algorithm"},
	{"unsafe_deserialization", CWEDeserial, "CWE-502", "High", "Unsafe deserialization", "Unsafe deserialization: can execute arbitrary code from untrusted data"},
	{"hardcoded_secret", CWEHardcoded, "CWE-798", "High", "Hardcoded secret", "Hardcoded secret detected: potential credential leak"},
	{"command_injection", CWECmdInject, "CWE-78", "High", "OS command injection", "Command injection vulnerability: executes shell commands"},
	{"path_traversal", CWEPathTraverse, "CWE-22", "High", "Path traversal", "Path traversal vulnerability: user-controlled file access"},
	{"memory_leak", CWEMemLeak, "CWE-401", "Medium", "Memory management", "Memory management risk: potential memory leak or unsafe operation"},
	{"weak_randomness", CWEWeakRand, "CWE-330", "Medium", "Weak randomness", "Weak randomness: not cryptographically secure"},
	{"sql_injection", CWESQLInject, "CWE-89", "High", "SQL injection", "SQL injection vulnerability: dynamic query construction detected"},
}

var rulesByCategory = func() map[float64]Rule {
	m := make(map[float64]Rule, len(Rules))
	for _, r := range Rules {
		m[r.Category] = r
	}
	return m
}()

// RuleByName returns the rule with the given ID.
func RuleByName(name string) (Rule, bool) {
	for _, r := range Rules {
		if r.Name == name {
			return r, true
		}
	}
	return Rule{}, false
}
