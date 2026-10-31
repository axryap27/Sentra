package engine

import (
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/c"
	"github.com/smacker/go-tree-sitter/cpp"
	"github.com/smacker/go-tree-sitter/csharp"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/php"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/rust"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
)

// Language identifies a supported source language.
type Language string

const (
	Python     Language = "python"
	JavaScript Language = "javascript"
	TypeScript Language = "typescript"
	Java       Language = "java"
	C          Language = "c"
	CPP        Language = "cpp"
	Go         Language = "go"
	PHP        Language = "php"
	CSharp     Language = "csharp"
	Rust       Language = "rust"
	Unknown    Language = "unknown"
)

// Languages lists every supported language, in feature-ID order.
var Languages = []Language{Python, JavaScript, TypeScript, Java, C, CPP, Go, PHP, CSharp, Rust}

// grammars is built once; tree-sitter Language values are immutable and shareable.
var grammars = map[Language]*sitter.Language{
	Python:     python.GetLanguage(),
	JavaScript: javascript.GetLanguage(),
	TypeScript: typescript.GetLanguage(),
	Java:       java.GetLanguage(),
	C:          c.GetLanguage(),
	CPP:        cpp.GetLanguage(),
	Go:         golang.GetLanguage(),
	PHP:        php.GetLanguage(),
	CSharp:     csharp.GetLanguage(),
	Rust:       rust.GetLanguage(),
}

var extensions = map[string]Language{
	".py": Python,
	".js": JavaScript, ".jsx": JavaScript, ".mjs": JavaScript, ".cjs": JavaScript,
	".ts": TypeScript, ".tsx": TypeScript,
	".java": Java,
	".c":    C,
	".cpp":  CPP, ".cc": CPP, ".cxx": CPP, ".hpp": CPP, ".h": CPP,
	".go":  Go,
	".php": PHP,
	".cs":  CSharp,
	".rs":  Rust,
}

// DetectLanguage maps a file path to a Language by extension.
func DetectLanguage(path string) Language {
	if l, ok := extensions[strings.ToLower(filepath.Ext(path))]; ok {
		return l
	}
	return Unknown
}

// Valid reports whether l is a supported language.
func (l Language) Valid() bool {
	_, ok := grammars[l]
	return ok
}

// id is the numeric language feature fed to the classifier (-1 if unknown).
func (l Language) id() float64 {
	for i, x := range Languages {
		if x == l {
			return float64(i)
		}
	}
	return -1
}
