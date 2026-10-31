// Command sentra-eval scores the engine against OWASP Benchmark v1.2.
//
//	go run ./cmd/sentra-eval -owasp /path/to/BenchmarkJava -split eval/owasp_split.json -subset test [-json out.json]
//
// Scoring follows the OWASP Benchmark scorecard: each test case is one Java file
// with one category and a ground-truth label. A case is "flagged" if the engine
// reports any finding whose rule matches the case's category. Per rule we report
// TP/FP/TN/FN, precision, recall (TPR), F1, false-positive rate, and the OWASP
// score (TPR - FPR; 0 is what random guessing gets).
//
// With -dump PATH it also writes every candidate's feature vector, labeled with
// the case's ground truth, as JSON lines for training (train split only).
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"sentra-analyzer/internal/engine"
)

type testCase struct {
	Category   string `json:"category"`
	Rule       string `json:"rule"`
	Vulnerable bool   `json:"vulnerable"`
	Split      string `json:"split"`
}

type splitFile struct {
	Cases map[string]testCase `json:"cases"`
}

// Counts is a confusion matrix for one rule.
type Counts struct {
	TP, FP, TN, FN int
}

// Metrics are derived from Counts.
type Metrics struct {
	Counts
	Cases      int     `json:"cases"`
	Precision  float64 `json:"precision"`
	Recall     float64 `json:"recall"`
	F1         float64 `json:"f1"`
	FPR        float64 `json:"fpr"`
	OWASPScore float64 `json:"owasp_score"`
}

func metrics(c Counts) Metrics {
	m := Metrics{Counts: c, Cases: c.TP + c.FP + c.TN + c.FN}
	div := func(a, b int) float64 {
		if b == 0 {
			return 0
		}
		return float64(a) / float64(b)
	}
	m.Precision = div(c.TP, c.TP+c.FP)
	m.Recall = div(c.TP, c.TP+c.FN)
	m.FPR = div(c.FP, c.FP+c.TN)
	if m.Precision+m.Recall > 0 {
		m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
	}
	m.OWASPScore = m.Recall - m.FPR
	return m
}

// Sample is one training row written by -dump.
type Sample struct {
	Case     string    `json:"case"`
	Rule     string    `json:"rule"`  // the sink's rule (candidate category)
	Label    int       `json:"label"` // 1 if this sink is the case's vulnerability
	Features []float64 `json:"features"`
}

func main() {
	owasp := flag.String("owasp", "", "BenchmarkJava checkout")
	splitPath := flag.String("split", "eval/owasp_split.json", "split file from eval/owasp_split.py")
	subset := flag.String("subset", "test", "train, test, or all")
	jsonOut := flag.String("json", "", "write metrics JSON here")
	dump := flag.String("dump", "", "write labeled candidate features (JSON lines) here")
	noModel := flag.Bool("no-model", false, "ablation: report every candidate that passes the deterministic gates")
	curveOut := flag.String("curve", "", "write a per-rule precision/recall sweep over thresholds (JSON) here")
	flag.Parse()

	var split splitFile
	b, err := os.ReadFile(*splitPath)
	check(err)
	check(json.Unmarshal(b, &split))

	names := make([]string, 0, len(split.Cases))
	for n, c := range split.Cases {
		if *subset == "all" || c.Split == *subset {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if *dump != "" && *subset != "train" {
		check(fmt.Errorf("-dump is only allowed on the train split"))
	}

	var dumpW *bufio.Writer
	if *dump != "" {
		f, err := os.Create(*dump)
		check(err)
		defer f.Close()
		dumpW = bufio.NewWriter(f)
		defer dumpW.Flush()
	}

	eng, err := engine.New(engine.Options{DisableModel: *noModel})
	check(err)
	// For -curve: the highest probability among each case's same-rule candidates (-1: none passed the gates).
	maxProb := map[string]float64{}
	counts := map[string]*Counts{}
	total := &Counts{}
	dir := filepath.Join(*owasp, "src/main/java/org/owasp/benchmark/testcode")
	for _, name := range names {
		tc := split.Cases[name]
		src, err := os.ReadFile(filepath.Join(dir, name+".java"))
		check(err)

		findings, err := eng.Analyze(engine.Java, src)
		check(err)
		if *curveOut != "" {
			scored, err := eng.Score(engine.Java, src)
			check(err)
			maxProb[name] = -1
			for _, s := range scored {
				if s.Rule.Name == tc.Rule && s.Probability > maxProb[name] {
					maxProb[name] = s.Probability
				}
			}
		}
		flagged := false
		for _, f := range findings {
			if f.Rule == tc.Rule {
				flagged = true
			}
		}

		if dumpW != nil {
			scored, err := eng.Score(engine.Java, src)
			check(err)
			for _, s := range scored {
				// Only sinks of the case's own category have a known label: the case is
				// vulnerable through that sink or it is not. Other sinks in the file are unlabeled.
				if s.Rule.Name != tc.Rule {
					continue
				}
				label := 0
				if tc.Vulnerable {
					label = 1
				}
				line, _ := json.Marshal(Sample{Case: name, Rule: s.Rule.Name, Label: label, Features: s.Features})
				dumpW.Write(append(line, '\n'))
			}
		}

		c := counts[tc.Rule]
		if c == nil {
			c = &Counts{}
			counts[tc.Rule] = c
		}
		for _, x := range []*Counts{c, total} {
			switch {
			case tc.Vulnerable && flagged:
				x.TP++
			case tc.Vulnerable:
				x.FN++
			case flagged:
				x.FP++
			default:
				x.TN++
			}
		}
	}

	out := map[string]Metrics{}
	rules := make([]string, 0, len(counts))
	for r, c := range counts {
		out[r] = metrics(*c)
		rules = append(rules, r)
	}
	sort.Strings(rules)
	out["_overall"] = metrics(*total)

	mode := "gates + model"
	if *noModel {
		mode = "gates only (model disabled)"
	}
	fmt.Printf("OWASP Benchmark v1.2, %s split, %d cases, %s\n\n", *subset, len(names), mode)
	fmt.Printf("%-18s %5s %4s %4s %4s %4s %6s %6s %6s %6s %6s\n", "rule", "cases", "TP", "FP", "TN", "FN", "prec", "recall", "F1", "FPR", "score")
	for _, r := range append(rules, "_overall") {
		m := out[r]
		fmt.Printf("%-18s %5d %4d %4d %4d %4d %6.3f %6.3f %6.3f %6.3f %+6.3f\n", r, m.Cases, m.TP, m.FP, m.TN, m.FN, m.Precision, m.Recall, m.F1, m.FPR, m.OWASPScore)
	}
	if *curveOut != "" {
		curves := map[string][]map[string]float64{}
		for _, r := range rules {
			for t := 0.0; t <= 0.951; t += 0.05 {
				var c Counts
				for _, name := range names {
					tc := split.Cases[name]
					if tc.Rule != r {
						continue
					}
					flagged := maxProb[name] >= 0 && maxProb[name] >= t
					switch {
					case tc.Vulnerable && flagged:
						c.TP++
					case tc.Vulnerable:
						c.FN++
					case flagged:
						c.FP++
					default:
						c.TN++
					}
				}
				m := metrics(c)
				curves[r] = append(curves[r], map[string]float64{"threshold": float64(int(t*100+0.5)) / 100, "precision": m.Precision, "recall": m.Recall, "fpr": m.FPR})
			}
		}
		b, _ := json.MarshalIndent(curves, "", " ")
		check(os.WriteFile(*curveOut, append(b, '\n'), 0o644))
	}
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(map[string]any{"subset": *subset, "mode": mode, "cases": len(names), "metrics": out}, "", "  ")
		check(os.WriteFile(*jsonOut, append(b, '\n'), 0o644))
	}
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "sentra-eval:", err)
		os.Exit(1)
	}
}
