package engine

import (
	"sort"
	"strings"
)

// sinkFlag constrains when a sink match counts.
type sinkFlag uint8

const (
	// needsWeakAlgo: an algorithm-taking API (MessageDigest.getInstance, hashlib.new,
	// crypto.createHash). Only a finding when an argument names a weak algorithm.
	needsWeakAlgo sinkFlag = 1 << iota
	// bareCall: only when called without a receiver, so eval(x) matches but
	// regex.exec(x) does not.
	bareCall
	// stringArg: only when the first argument is a string (setTimeout("code"), not setTimeout(fn)).
	stringArg
)

// sink is one dangerous API. Patterns containing '.' or "::" match as a
// case-insensitive substring of the callee; other patterns match the callee's last
// segment exactly (case-insensitive).
type sink struct {
	pattern string
	cat     float64
	langs   []Language // nil: every language
	flags   sinkFlag
}

var (
	jsLike   = []Language{JavaScript, TypeScript}
	cLike    = []Language{C, CPP}
	javaOnly = []Language{Java}
)

var sinks = []sink{
	// Code injection (CWE-94)
	{"eval", CWECodeInject, []Language{Python, JavaScript, TypeScript, PHP}, bareCall},
	{"exec", CWECodeInject, []Language{Python}, bareCall},
	{"Function", CWECodeInject, jsLike, bareCall},
	{"setTimeout", CWECodeInject, jsLike, stringArg},
	{"setInterval", CWECodeInject, jsLike, stringArg},
	{"create_function", CWECodeInject, []Language{PHP}, 0},

	// OS command injection (CWE-78)
	{"os.system", CWECmdInject, nil, 0},
	{"os.popen", CWECmdInject, nil, 0},
	{"subprocess.call", CWECmdInject, nil, 0},
	{"subprocess.Popen", CWECmdInject, nil, 0},
	{"subprocess.run", CWECmdInject, nil, 0},
	{"subprocess.check_output", CWECmdInject, nil, 0},
	{"subprocess.check_call", CWECmdInject, nil, 0},
	{"shell=True", CWECmdInject, []Language{Python}, 0},
	{"system", CWECmdInject, []Language{C, CPP, PHP}, bareCall},
	{"popen", CWECmdInject, []Language{C, CPP, PHP}, bareCall},
	{"shell_exec", CWECmdInject, []Language{PHP}, 0},
	{"passthru", CWECmdInject, []Language{PHP}, 0},
	{"proc_open", CWECmdInject, []Language{PHP}, 0},
	{"exec", CWECmdInject, []Language{PHP}, bareCall},
	{"exec", CWECmdInject, javaOnly, 0}, // Runtime.getRuntime().exec, r.exec
	{"ProcessBuilder", CWECmdInject, javaOnly, 0},
	{"command", CWECmdInject, javaOnly, 0}, // ProcessBuilder.command(...)
	{"child_process.exec", CWECmdInject, jsLike, 0},
	{"execSync", CWECmdInject, jsLike, 0},
	{"exec", CWECmdInject, jsLike, bareCall}, // const { exec } = require('child_process')
	{"exec.Command", CWECmdInject, []Language{Go}, 0},
	{"Command::new", CWECmdInject, []Language{Rust}, 0},
	{"Process.Start", CWECmdInject, []Language{CSharp}, 0},

	// XSS (CWE-79)
	{"innerHTML", CWEXSS, jsLike, 0},
	{"outerHTML", CWEXSS, jsLike, 0},
	{"dangerouslySetInnerHTML", CWEXSS, jsLike, 0},
	{"insertAdjacentHTML", CWEXSS, jsLike, 0},
	{"document.write", CWEXSS, jsLike, 0},
	{"getWriter().print", CWEXSS, javaOnly, 0}, // also println, printf
	{"getWriter().write", CWEXSS, javaOnly, 0},
	{"getWriter().format", CWEXSS, javaOnly, 0},
	{"getWriter().append", CWEXSS, javaOnly, 0},
	{"mark_safe", CWEXSS, []Language{Python}, 0},

	// Buffer overflow (CWE-120)
	{"strcpy", CWEBufferOvfl, cLike, 0},
	{"strcat", CWEBufferOvfl, cLike, 0},
	{"sprintf", CWEBufferOvfl, cLike, 0},
	{"vsprintf", CWEBufferOvfl, cLike, 0},
	{"gets", CWEBufferOvfl, cLike, 0},
	{"scanf", CWEBufferOvfl, cLike, 0},
	{"memcpy", CWEBufferOvfl, cLike, 0},

	// Weak cryptography (CWE-327)
	{"md5", CWEWeakCrypto, nil, 0},
	{"sha1", CWEWeakCrypto, nil, 0},
	{"md5Hex", CWEWeakCrypto, javaOnly, 0},
	{"sha1Hex", CWEWeakCrypto, javaOnly, 0},
	{"md5.New", CWEWeakCrypto, []Language{Go}, 0},
	{"md5.Sum", CWEWeakCrypto, []Language{Go}, 0},
	{"sha1.New", CWEWeakCrypto, []Language{Go}, 0},
	{"sha1.Sum", CWEWeakCrypto, []Language{Go}, 0},
	{"des.NewCipher", CWEWeakCrypto, []Language{Go}, 0},
	{"rc4.NewCipher", CWEWeakCrypto, []Language{Go}, 0},
	{"MD5.Create", CWEWeakCrypto, []Language{CSharp}, 0},
	{"SHA1.Create", CWEWeakCrypto, []Language{CSharp}, 0},
	{"DES.new", CWEWeakCrypto, []Language{Python}, 0},
	{"ARC4.new", CWEWeakCrypto, []Language{Python}, 0},
	{"hashlib.new", CWEWeakCrypto, []Language{Python}, needsWeakAlgo},
	{"MessageDigest.getInstance", CWEWeakCrypto, javaOnly, needsWeakAlgo},
	{"Cipher.getInstance", CWEWeakCrypto, javaOnly, needsWeakAlgo},
	{"KeyGenerator.getInstance", CWEWeakCrypto, javaOnly, needsWeakAlgo},
	{"SecretKeyFactory.getInstance", CWEWeakCrypto, javaOnly, needsWeakAlgo},
	{"createHash", CWEWeakCrypto, jsLike, needsWeakAlgo},
	{"createCipheriv", CWEWeakCrypto, jsLike, needsWeakAlgo},
	{"createCipher", CWEWeakCrypto, jsLike, needsWeakAlgo},

	// Unsafe deserialization (CWE-502)
	{"pickle.load", CWEDeserial, []Language{Python}, 0}, // also pickle.loads
	{"cPickle.load", CWEDeserial, []Language{Python}, 0},
	{"dill.load", CWEDeserial, []Language{Python}, 0},
	{"jsonpickle.decode", CWEDeserial, []Language{Python}, 0},
	{"yaml.load", CWEDeserial, []Language{Python}, 0}, // except Loader=SafeLoader (see gates)
	{"yaml.unsafe_load", CWEDeserial, []Language{Python}, 0},
	{"marshal.load", CWEDeserial, []Language{Python}, 0},
	{"ObjectInputStream", CWEDeserial, javaOnly, 0},
	{"XMLDecoder", CWEDeserial, javaOnly, 0},
	{"unserialize", CWEDeserial, []Language{PHP}, 0},
	{"BinaryFormatter", CWEDeserial, []Language{CSharp}, 0},

	// Path traversal (CWE-22)
	{"open", CWEPathTraverse, []Language{Python}, bareCall},
	{"File", CWEPathTraverse, javaOnly, 0},
	{"FileInputStream", CWEPathTraverse, javaOnly, 0},
	{"FileOutputStream", CWEPathTraverse, javaOnly, 0},
	{"FileReader", CWEPathTraverse, javaOnly, 0},
	{"FileWriter", CWEPathTraverse, javaOnly, 0},
	{"RandomAccessFile", CWEPathTraverse, javaOnly, 0},
	{"Paths.get", CWEPathTraverse, javaOnly, 0},
	{"Path.of", CWEPathTraverse, javaOnly, 0},
	{"fs.readFile", CWEPathTraverse, jsLike, 0}, // also readFileSync
	{"fs.writeFile", CWEPathTraverse, jsLike, 0},
	{"fs.createReadStream", CWEPathTraverse, jsLike, 0},
	{"sendFile", CWEPathTraverse, jsLike, 0},
	{"fopen", CWEPathTraverse, []Language{C, CPP, PHP}, 0},
	{"file_get_contents", CWEPathTraverse, []Language{PHP}, 0},
	{"os.Open", CWEPathTraverse, []Language{Go}, 0},
	{"os.ReadFile", CWEPathTraverse, []Language{Go}, 0},

	// Memory management (CWE-401). Gated on a missing free() in the same function.
	{"malloc", CWEMemLeak, cLike, bareCall},
	{"calloc", CWEMemLeak, cLike, bareCall},
	{"realloc", CWEMemLeak, cLike, bareCall},

	// Weak randomness (CWE-330)
	{"Math.random", CWEWeakRand, jsLike, 0},
	{"random.random", CWEWeakRand, []Language{Python}, 0},
	{"Random", CWEWeakRand, []Language{Java, CSharp}, 0}, // new java.util.Random(), new Random()
	{"ThreadLocalRandom.current", CWEWeakRand, javaOnly, 0},
	{"rand", CWEWeakRand, []Language{C, CPP, PHP}, bareCall},
	{"mt_rand", CWEWeakRand, []Language{PHP}, 0},

	// SQL injection (CWE-89). Gated on an argument built by concatenation/formatting.
	{"execute", CWESQLInject, nil, 0},
	{"executemany", CWESQLInject, []Language{Python}, 0},
	{"executeQuery", CWESQLInject, nil, 0},
	{"executeUpdate", CWESQLInject, nil, 0},
	{"executeLargeUpdate", CWESQLInject, javaOnly, 0},
	{"addBatch", CWESQLInject, javaOnly, 0},
	{"prepareStatement", CWESQLInject, javaOnly, 0},
	{"prepareCall", CWESQLInject, javaOnly, 0},
	{"query", CWESQLInject, nil, 0},
	{"queryForObject", CWESQLInject, javaOnly, 0},
	{"queryForList", CWESQLInject, javaOnly, 0},
	{"queryForMap", CWESQLInject, javaOnly, 0},
	{"queryForRowSet", CWESQLInject, javaOnly, 0},
	{"batchUpdate", CWESQLInject, javaOnly, 0},
	{"Template.update", CWESQLInject, javaOnly, 0}, // jdbcTemplate.update
	{"objects.raw", CWESQLInject, []Language{Python}, 0},
	{"QueryRow", CWESQLInject, []Language{Go}, 0},
	{"Exec", CWESQLInject, []Language{Go}, 0},
	{"mysqli_query", CWESQLInject, []Language{PHP}, 0},
	{"mysql_query", CWESQLInject, []Language{PHP}, 0},
	{"pg_query", CWESQLInject, []Language{PHP}, 0},
	{"SqlCommand", CWESQLInject, []Language{CSharp}, 0},
}

// Lowercased index, built once.
type indexedSink struct {
	sink
	lower string
}

var (
	compoundSinks []indexedSink            // dotted patterns, longest first
	segmentSinks  map[string][]indexedSink // last-segment patterns
)

func init() {
	segmentSinks = make(map[string][]indexedSink)
	for _, s := range sinks {
		is := indexedSink{s, strings.ToLower(s.pattern)}
		if strings.Contains(s.pattern, ".") || strings.Contains(s.pattern, "::") || strings.Contains(s.pattern, "=") {
			compoundSinks = append(compoundSinks, is)
		} else {
			segmentSinks[is.lower] = append(segmentSinks[is.lower], is)
		}
	}
	sort.SliceStable(compoundSinks, func(i, j int) bool { return len(compoundSinks[i].lower) > len(compoundSinks[j].lower) })
}

func (s *sink) appliesTo(lang Language) bool {
	if s.langs == nil {
		return true
	}
	for _, l := range s.langs {
		if l == lang {
			return true
		}
	}
	return false
}

// bareReceivers are receivers that still count as a "bare" call.
var bareReceivers = map[string]bool{"window": true, "globalThis": true, "global": true, "builtins": true}

// matchSink returns the sink a callee or assignment target refers to, or nil.
func matchSink(name string, lang Language) *sink {
	if name == "" {
		return nil
	}
	lower := strings.ToLower(name)
	for i := range compoundSinks {
		s := &compoundSinks[i]
		if s.appliesTo(lang) && strings.Contains(lower, s.lower) {
			return &s.sink
		}
	}
	receiver, last := "", name
	if i := strings.LastIndexAny(name, ".>:"); i >= 0 {
		receiver, last = strings.TrimRight(name[:i], "-:"), name[i+1:]
	}
	for _, s := range segmentSinks[strings.ToLower(last)] {
		if !s.appliesTo(lang) {
			continue
		}
		if s.flags&bareCall != 0 && receiver != "" && !bareReceivers[receiver] {
			continue
		}
		return &s.sink
	}
	return nil
}
