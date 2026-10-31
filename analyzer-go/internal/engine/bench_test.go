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
