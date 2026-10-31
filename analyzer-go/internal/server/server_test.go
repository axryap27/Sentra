package server

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sentra-analyzer/internal/engine"
)

func roundTrip(t *testing.T, input string) map[string]Response {
	t.Helper()
	r, w := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- New(engine.Default(), 4).Serve(strings.NewReader(input), w)
		w.Close()
	}()
	out := map[string]Response{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		var resp struct {
			ID     json.RawMessage `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  string          `json:"error"`
		}
		if err := json.Unmarshal(sc.Bytes(), &resp); err != nil {
			t.Fatalf("bad response line %q: %v", sc.Text(), err)
		}
		out[string(resp.ID)] = Response{ID: resp.ID, Result: resp.Result, Error: resp.Error}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return out
}

func findings(t *testing.T, r Response) []engine.Finding {
	t.Helper()
	var res AnalyzeResult
	if err := json.Unmarshal(r.Result.(json.RawMessage), &res); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	return res.Findings
}

func TestServePipelined(t *testing.T) {
	var in strings.Builder
	for i := 1; i <= 50; i++ {
		req, _ := json.Marshal(map[string]any{"id": i, "method": "analyze", "params": map[string]any{
			"language": "python", "content": "import os\nos.system('rm ' + input())\n",
		}})
		in.Write(append(req, '\n'))
	}
	out := roundTrip(t, in.String())
	if len(out) != 50 {
		t.Fatalf("got %d responses, want 50", len(out))
	}
	for id, r := range out {
		if r.Error != "" {
			t.Errorf("id %s: %s", id, r.Error)
		} else if fs := findings(t, r); len(fs) != 1 || fs[0].Rule != "command_injection" {
			t.Errorf("id %s: findings %v", id, fs)
		}
	}
}

func TestServeErrorsAndMethods(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.js")
	if err := os.WriteFile(path, []byte("eval(location.hash)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pathJSON, _ := json.Marshal(path)
	in := strings.Join([]string{
		`{"id":1,"method":"version"}`,
		`{"id":2,"method":"analyze","params":{"language":"cobol","content":"x"}}`,
		`{"id":3,"method":"nope"}`,
		`not json`,
		`{"id":4,"method":"analyze","params":{"path":` + string(pathJSON) + `}}`,
		`{"id":5,"method":"analyze","params":{"language":"python","content":""}}`,
		`{"id":6,"method":"analyze","params":{}}`,
		`{"id":7,"method":"shutdown"}`,
		`{"id":8,"method":"version"}`, // after shutdown: never answered
	}, "\n") + "\n"
	out := roundTrip(t, in)

	if !strings.Contains(string(out["1"].Result.(json.RawMessage)), engine.Version) {
		t.Errorf("version: %+v", out["1"])
	}
	if !strings.Contains(out["2"].Error, "unsupported language") {
		t.Errorf("bad language: %+v", out["2"])
	}
	if !strings.Contains(out["3"].Error, "unknown method") {
		t.Errorf("unknown method: %+v", out["3"])
	}
	if !strings.Contains(out["null"].Error, "malformed") {
		t.Errorf("malformed request: %+v", out["null"])
	}
	if fs := findings(t, out["4"]); len(fs) != 1 || fs[0].Rule != "code_injection" {
		t.Errorf("path request: %v", fs)
	}
	if fs := findings(t, out["5"]); fs == nil || len(fs) != 0 {
		t.Errorf("empty content should return [] not null: %v", fs)
	}
	if !strings.Contains(out["6"].Error, "requires") {
		t.Errorf("missing content/path: %+v", out["6"])
	}
	if _, ok := out["8"]; ok {
		t.Error("request after shutdown was answered")
	}
}

func TestReadLineTooLong(t *testing.T) {
	long := `{"id":1,"method":"analyze","params":{"language":"python","content":"` + strings.Repeat("x", MaxRequestBytes) + `"}}`
	out := roundTrip(t, long+"\n"+`{"id":2,"method":"version"}`+"\n")
	if !strings.Contains(out["null"].Error, "exceeds") {
		t.Errorf("oversized request: %+v", out["null"])
	}
	if out["2"].Error != "" || out["2"].Result == nil {
		t.Errorf("request after an oversized one should still work: %+v", out["2"])
	}
}
