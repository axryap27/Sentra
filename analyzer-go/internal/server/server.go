// Package server implements the analyzer daemon: newline-delimited JSON
// requests on stdin, responses on stdout, processed concurrently.
//
// Request:  {"id": 1, "method": "analyze", "params": {"language": "python", "content": "...", "path": "a.py"}}
// Response: {"id": 1, "result": {"findings": [...]}}  or  {"id": 1, "error": "..."}
//
// Methods:
//
//	analyze   params.content is analyzed if present, otherwise params.path is read
//	          from disk. params.language is inferred from params.path if empty.
//	version   returns {"version": "..."}
//	shutdown  stops reading; in-flight requests finish, then Serve returns.
//
// Responses may arrive out of order; clients match them by id.
package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"sync"

	"sentra-analyzer/internal/engine"
)

// Request is one line of input.
type Request struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params Params          `json:"params"`
}

// Params holds the arguments for analyze.
type Params struct {
	Language string  `json:"language"`
	Path     string  `json:"path"`
	Content  *string `json:"content"`
}

// Response is one line of output.
type Response struct {
	ID     json.RawMessage `json:"id"`
	Result any             `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// AnalyzeResult is the result of the analyze method.
type AnalyzeResult struct {
	Findings []engine.Finding `json:"findings"`
}

// MaxRequestBytes bounds a single request line (source is JSON-escaped, so
// this allows files somewhat larger than the extension's default 1 MB limit).
const MaxRequestBytes = 16 << 20

// Server dispatches requests to the engine with bounded concurrency.
type Server struct {
	eng *engine.Engine
	sem chan struct{}
}

// New returns a server that runs at most workers analyses at once.
func New(eng *engine.Engine, workers int) *Server {
	return &Server{eng: eng, sem: make(chan struct{}, max(1, workers))}
}

// Serve reads requests from r until EOF or shutdown and writes responses to w.
func (s *Server) Serve(r io.Reader, w io.Writer) error {
	in := bufio.NewReaderSize(r, 256*1024)
	out := bufio.NewWriter(w)
	enc := json.NewEncoder(out)
	var mu sync.Mutex
	send := func(resp Response) {
		mu.Lock()
		defer mu.Unlock()
		if err := enc.Encode(resp); err != nil { // Encode appends '\n'
			fmt.Fprintln(os.Stderr, "sentra-analyzer: write:", err)
		}
		out.Flush()
	}

	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		line, err := readLine(in)
		if len(line) > 0 {
			var req Request
			if jerr := json.Unmarshal(line, &req); jerr != nil {
				send(Response{ID: json.RawMessage("null"), Error: "malformed request: " + jerr.Error()})
			} else if req.Method == "shutdown" {
				send(Response{ID: req.ID, Result: struct{}{}})
				return nil
			} else {
				s.sem <- struct{}{}
				wg.Add(1)
				go func() {
					defer func() { <-s.sem; wg.Done() }()
					send(s.handle(req))
				}()
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil // client went away
			}
			if errors.Is(err, errLineTooLong) {
				send(Response{ID: json.RawMessage("null"), Error: err.Error()})
				continue
			}
			return err
		}
	}
}

var errLineTooLong = fmt.Errorf("request exceeds %d bytes", MaxRequestBytes)

// readLine returns the next newline-terminated line without the newline. Lines
// over MaxRequestBytes are discarded and reported as errLineTooLong.
func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(buf)+len(chunk) > MaxRequestBytes {
			for errors.Is(err, bufio.ErrBufferFull) { // drain the rest of the line
				_, err = r.ReadSlice('\n')
			}
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, err
			}
			return nil, errLineTooLong
		}
		buf = append(buf, chunk...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if n := len(buf); n > 0 && buf[n-1] == '\n' {
			buf = buf[:n-1]
		}
		return buf, err
	}
}

func (s *Server) handle(req Request) (resp Response) {
	resp.ID = req.ID
	defer func() {
		// A bug in one analysis must not take the daemon (and every open editor) down.
		if p := recover(); p != nil {
			fmt.Fprintf(os.Stderr, "sentra-analyzer: panic: %v\n%s", p, debug.Stack())
			resp = Response{ID: req.ID, Error: fmt.Sprintf("internal error: %v", p)}
		}
	}()

	switch req.Method {
	case "version":
		resp.Result = map[string]string{"version": engine.Version}
	case "analyze":
		findings, err := s.analyze(req.Params)
		if err != nil {
			resp.Error = err.Error()
			return
		}
		if findings == nil {
			findings = []engine.Finding{}
		}
		resp.Result = AnalyzeResult{Findings: findings}
	default:
		resp.Error = fmt.Sprintf("unknown method %q", req.Method)
	}
	return
}

func (s *Server) analyze(p Params) ([]engine.Finding, error) {
	lang := engine.Language(p.Language)
	if p.Language == "" {
		lang = engine.DetectLanguage(p.Path)
	}
	if !lang.Valid() {
		return nil, fmt.Errorf("unsupported language %q", string(lang))
	}
	var src []byte
	if p.Content != nil {
		src = []byte(*p.Content)
	} else if p.Path != "" {
		b, err := os.ReadFile(p.Path)
		if err != nil {
			return nil, err
		}
		src = b
	} else {
		return nil, errors.New("analyze requires params.content or params.path")
	}
	return s.eng.Analyze(lang, src)
}
