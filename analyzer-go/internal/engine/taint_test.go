package engine

import (
	"reflect"
	"testing"
)

func TestIdentifiers(t *testing.T) {
	var names []string
	for _, id := range identifiers(`run(cmd, shell=True, "lit {x}", f"a {y} b", obj.field, 'q')`) {
		switch {
		case id.literal:
			names = append(names, "L:"+id.name)
		case id.member:
			names = append(names, "M:"+id.name)
		case id.kwarg:
			names = append(names, "K:"+id.name)
		default:
			names = append(names, id.name)
		}
	}
	want := []string{"run", "cmd", "K:shell", "True", "L:lit {x}", "L:a {y} b", "y", "obj", "M:field", "L:q"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("identifiers =\n %v\nwant\n %v", names, want)
	}
}

func TestAnalyzeExpr(t *testing.T) {
	w := &walker{frames: []frame{{}}}
	w.pushFrame("(self, user_id, *args)")
	w.assign("safe", valueInfo{constant: true})
	w.assign("alg", w.analyzeExpr(`"MD5"`))

	cases := []struct {
		expr     string
		flags    taint
		constant bool
	}{
		{`"SELECT 1"`, 0, true},
		{`safe`, 0, true},
		{`user_id`, tParam, false},
		{`"x" + user_id`, tParam | tConcat, false},
		{`request.args.get("q")`, tInput, false},
		{`"%s" % user_id`, tParam | tConcat, false},
		{`f"{user_id}"`, tParam | tConcat, false},
		{`alg`, tWeakAlgo, true},
		{`escape(request.args["q"])`, 0, false}, // sanitized
		{`self.name`, 0, false},                 // receiver is not a tainted parameter
	}
	for _, c := range cases {
		got := w.analyzeExpr(c.expr)
		if got.flags != c.flags || got.constant != c.constant {
			t.Errorf("analyzeExpr(%s) = {flags:%04b constant:%v}, want {flags:%04b constant:%v}", c.expr, got.flags, got.constant, c.flags, c.constant)
		}
	}
}

func TestWeakUpdateInBranch(t *testing.T) {
	w := &walker{frames: []frame{{}}}
	w.assign("p", valueInfo{flags: tInput})
	w.sc.branchDepth = 1 // inside `if (p == null)`
	w.assign("p", valueInfo{constant: true})
	if v, _ := w.lookup("p"); v.flags&tInput == 0 {
		t.Error("assignment inside a branch erased taint (want a weak update)")
	}
	w.sc.branchDepth = 0
	w.assign("p", valueInfo{constant: true})
	if v, _ := w.lookup("p"); v.flags != 0 || !v.constant {
		t.Error("straight-line assignment should overwrite (strong update)")
	}
}

func TestAssignedNames(t *testing.T) {
	for in, want := range map[string][]string{
		"x": {"x"}, "a, b": {"a", "b"}, "String sql": {"sql"}, "*buf": {"buf"},
		"self.x": nil, "arr[i]": nil, "$name": {"$name"},
	} {
		if got := assignedNames(in); !reflect.DeepEqual(got, want) {
			t.Errorf("assignedNames(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestContainsConcatPattern(t *testing.T) {
	for in, want := range map[string]bool{
		`"a" + b`:                      true,
		`"VALUES ('foo','" + p + "')"`: true, // single quotes inside a double-quoted string
		`"a+b"`:                        false,
		`'it''s'`:                      false,
		"`${x}`":                       true,
		`f"{x}"`:                       true,
	} {
		if got := containsConcatPattern(in); got != want {
			t.Errorf("containsConcatPattern(%s) = %v, want %v", in, got, want)
		}
	}
}

func TestMatchSink(t *testing.T) {
	cases := []struct {
		name string
		lang Language
		cat  float64
	}{
		{"os.system", Python, CWECmdInject},
		{"eval", JavaScript, CWECodeInject},
		{"re.exec", JavaScript, CWENone},
		{"exec", JavaScript, CWECmdInject},
		{"Runtime.getRuntime().exec", Java, CWECmdInject},
		{"exec", Python, CWECodeInject},
		{"response.getWriter().println", Java, CWEXSS},
		{"java.util.Random", Java, CWEWeakRand},
		{"java.security.SecureRandom", Java, CWENone},
		{"sprintf", PHP, CWENone},
		{"sprintf", C, CWEBufferOvfl},
		{"pickle.loads", Python, CWEDeserial},
		{"Command::new", Rust, CWECmdInject},
	}
	for _, c := range cases {
		got := 0.0
		if s := matchSink(c.name, c.lang); s != nil {
			got = s.cat
		}
		if got != c.cat {
			t.Errorf("matchSink(%q, %s) = %v, want %v", c.name, c.lang, got, c.cat)
		}
	}
}

func TestIdentWords(t *testing.T) {
	for in, want := range map[string][]string{
		"dbPassword": {"db", "password"}, "API_KEY": {"api", "key"}, "self.secret_key": {"secret", "key"},
	} {
		if got := identWords(in); !reflect.DeepEqual(got, want) {
			t.Errorf("identWords(%q) = %v, want %v", in, got, want)
		}
	}
}
