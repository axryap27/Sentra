package engine

import (
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkAnalyze runs the engine over every file in test_files/.
// Set SENTRA_CORPUS to benchmark a different directory.
func BenchmarkAnalyze(b *testing.B) {
	root := os.Getenv("SENTRA_CORPUS")
	if root == "" {
		root = "../../../test_files"
	}
	type file struct {
		lang Language
		src  []byte
	}
	var files []file
	var total int64
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Size() > 1<<20 {
			return nil
		}
		if l := DetectLanguage(p); l.Valid() {
			src, _ := os.ReadFile(p)
			files = append(files, file{l, src})
			total += int64(len(src))
		}
		return nil
	})
	if len(files) == 0 {
		b.Skip("no files")
	}
	eng := Default()
	b.SetBytes(total)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, f := range files {
			if _, err := eng.Analyze(f.lang, f.src); err != nil {
				b.Fatal(err)
			}
		}
	}
}

// BenchmarkProba measures Random Forest inference for one candidate.
func BenchmarkProba(b *testing.B) {
	clf, err := GetClassifier()
	if err != nil {
		b.Fatal(err)
	}
	fv := make([]float64, NumFeatures)
	fv[0], fv[2], fv[15], fv[17], fv[14] = CWESQLInject, 1, 1, 1, 3
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		clf.Proba(fv, "sql_injection")
	}
}
