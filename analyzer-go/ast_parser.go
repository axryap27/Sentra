package main

import (
	"context"
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

// CandidateNode represents an AST node that might be a security-relevant site.
type CandidateNode struct {
	Name     string // function/method name or identifier
	Line     int    // 1-based line number
	NodeType string // tree-sitter node type (e.g. "call_expression")

	// Context extracted from the AST
	ArgCount           int
	HasStringConcatArg bool
	ParentFunctionName string
	IsInComment        bool
	IsInTryCatch       bool
	IsInConditional    bool
	IsInLoop           bool
	IsPublicFunction   bool
	NodeDepth          int
	RawLine            string // the original source line for fallback heuristics
	ArgSource          string // raw text of argument list
	AssignedIdentifier string // for assignments: the variable name on the left side
	AssignedValue      string // for assignments: the raw value on the right side
}

// ASTParser wraps tree-sitter to parse source and extract candidate nodes.
type ASTParser struct {
	language Language
	parser   *sitter.Parser
	lines    []string // source lines for raw line lookup
}

// NewASTParser creates a parser for the given language.
func NewASTParser(lang Language) *ASTParser {
	p := sitter.NewParser()
	p.SetLanguage(treeSitterLanguage(lang))
	return &ASTParser{language: lang, parser: p}
}

// treeSitterLanguage maps our Language enum to a tree-sitter grammar.
func treeSitterLanguage(lang Language) *sitter.Language {
	switch lang {
	case LanguagePython:
		return python.GetLanguage()
	case LanguageJavaScript:
		return javascript.GetLanguage()
	case LanguageTypeScript:
		return typescript.GetLanguage()
	case LanguageJava:
		return java.GetLanguage()
	case LanguageC:
		return c.GetLanguage()
	case LanguageCPP:
		return cpp.GetLanguage()
	case LanguageGo:
		return golang.GetLanguage()
	case LanguagePHP:
		return php.GetLanguage()
	case LanguageCSharp:
		return csharp.GetLanguage()
	case LanguageRust:
		return rust.GetLanguage()
	default:
		return python.GetLanguage()
	}
}

// Parse parses source code and returns candidate nodes for security analysis.
func (ap *ASTParser) Parse(source []byte) []CandidateNode {
	tree, err := ap.parser.ParseCtx(context.Background(), nil, source)
	if err != nil || tree == nil {
		return nil
	}
	root := tree.RootNode()
	if root == nil {
		return nil
	}

	ap.lines = strings.Split(string(source), "\n")

	var candidates []CandidateNode
	ap.walk(root, source, 0, &candidates)
	return candidates
}

// getSourceLine returns the source line (0-indexed row).
func (ap *ASTParser) getSourceLine(row int) string {
	if row >= 0 && row < len(ap.lines) {
		return ap.lines[row]
	}
	return ""
}

// walk recursively traverses the AST and collects candidate nodes.
func (ap *ASTParser) walk(node *sitter.Node, source []byte, depth int, candidates *[]CandidateNode) {
	if node == nil {
		return
	}

	nodeType := node.Type()

	// Collect function/method calls
	if ap.isCallNode(nodeType) {
		if c := ap.extractCallCandidate(node, source, depth); c != nil {
			*candidates = append(*candidates, *c)
		}
	}

	// Collect assignments (for hardcoded secrets + property assignments like innerHTML)
	if ap.isAssignmentNode(nodeType) {
		if c := ap.extractAssignmentCandidate(node, source, depth); c != nil {
			*candidates = append(*candidates, *c)
		}
	}

	// Collect keyword arguments (e.g. Python's shell=True)
	if nodeType == "keyword_argument" {
		if c := ap.extractKeywordArgCandidate(node, source, depth); c != nil {
			*candidates = append(*candidates, *c)
		}
	}

	// Recurse into children
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		ap.walk(child, source, depth+1, candidates)
	}
}

// isCallNode checks if the node type represents a function/method call.
func (ap *ASTParser) isCallNode(nodeType string) bool {
	switch nodeType {
	case "call_expression", "call", "invocation_expression",
		"method_invocation", "function_call_expression",
		"macro_invocation",
		"object_creation_expression", "new_expression": // Java/JS constructors
		return true
	}
	return false
}

// isAssignmentNode checks if the node represents an assignment.
func (ap *ASTParser) isAssignmentNode(nodeType string) bool {
	switch nodeType {
	case "assignment", "assignment_expression", "variable_declaration",
		"variable_declarator", "let_declaration", "short_var_declaration",
		"augmented_assignment":
		return true
	}
	return false
}

// extractCallCandidate builds a CandidateNode from a function call AST node.
func (ap *ASTParser) extractCallCandidate(node *sitter.Node, source []byte, depth int) *CandidateNode {
	funcName := ap.extractFunctionName(node, source)
	if funcName == "" {
		return nil
	}

	line := int(node.StartPoint().Row) + 1

	candidate := &CandidateNode{
		Name:      funcName,
		Line:      line,
		NodeType:  node.Type(),
		NodeDepth: depth,
		RawLine:   ap.getSourceLine(int(node.StartPoint().Row)),
	}

	// Extract argument info
	candidate.ArgCount, candidate.HasStringConcatArg, candidate.ArgSource = ap.extractArgInfo(node, source)

	// Extract context by walking up the tree
	ap.extractContext(node, source, candidate)

	return candidate
}

// extractAssignmentCandidate builds a CandidateNode from an assignment AST node.
func (ap *ASTParser) extractAssignmentCandidate(node *sitter.Node, source []byte, depth int) *CandidateNode {
	var identifier, value string

	// Try named fields first (left/right for assignment_expression)
	if left := node.ChildByFieldName("left"); left != nil {
		text := nodeText(left, source)
		identifier = text
		// For member expressions like obj.innerHTML, extract the property name
		if left.Type() == "member_expression" || left.Type() == "attribute" {
			identifier = text // keep full text like "document.getElementById('output').innerHTML"
		}
	}
	if right := node.ChildByFieldName("right"); right != nil {
		value = nodeText(right, source)
	}

	// Fallback: iterate children
	if identifier == "" {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child == nil {
				continue
			}
			childType := child.Type()

			switch childType {
			case "identifier", "property_identifier", "field_identifier":
				if identifier == "" {
					identifier = nodeText(child, source)
				}
			case "member_expression", "attribute":
				if identifier == "" {
					identifier = nodeText(child, source)
				}
			case "string", "string_literal", "template_string", "raw_string_literal",
				"interpreted_string_literal", "encapsed_string":
				if value == "" {
					value = nodeText(child, source)
				}
			}
		}
	}

	if identifier == "" {
		return nil
	}

	line := int(node.StartPoint().Row) + 1

	candidate := &CandidateNode{
		Name:               identifier,
		Line:               line,
		NodeType:           node.Type(),
		NodeDepth:          depth,
		RawLine:            ap.getSourceLine(int(node.StartPoint().Row)),
		AssignedIdentifier: identifier,
		AssignedValue:      value,
	}

	ap.extractContext(node, source, candidate)
	return candidate
}

// extractKeywordArgCandidate handles Python keyword arguments like shell=True.
func (ap *ASTParser) extractKeywordArgCandidate(node *sitter.Node, source []byte, depth int) *CandidateNode {
	text := nodeText(node, source)
	if !strings.Contains(text, "shell") || !strings.Contains(text, "True") {
		return nil
	}

	line := int(node.StartPoint().Row) + 1
	candidate := &CandidateNode{
		Name:      "shell=True",
		Line:      line,
		NodeType:  "keyword_argument",
		NodeDepth: depth,
		RawLine:   ap.getSourceLine(int(node.StartPoint().Row)),
	}
	ap.extractContext(node, source, candidate)
	return candidate
}

// extractFunctionName gets the function/method name from a call node.
func (ap *ASTParser) extractFunctionName(node *sitter.Node, source []byte) string {
	// Try named field "function" first (most reliable for Python/JS/C)
	if fn := node.ChildByFieldName("function"); fn != nil {
		return nodeText(fn, source)
	}

	// For Java method_invocation: combine object.name (e.g., "Runtime.getRuntime().exec")
	if name := node.ChildByFieldName("name"); name != nil {
		nameText := nodeText(name, source)
		if obj := node.ChildByFieldName("object"); obj != nil {
			return nodeText(obj, source) + "." + nameText
		}
		return nameText
	}

	if method := node.ChildByFieldName("method"); method != nil {
		return nodeText(method, source)
	}

	// For constructor expressions: get the type being constructed
	if typ := node.ChildByFieldName("type"); typ != nil {
		return nodeText(typ, source)
	}

	// Fallback: iterate direct children
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		childType := child.Type()

		switch childType {
		case "identifier":
			return nodeText(child, source)
		case "member_expression", "attribute", "field_expression",
			"scoped_identifier", "qualified_name", "member_access_expression":
			return nodeText(child, source)
		case "type_identifier", "generic_type":
			return nodeText(child, source)
		}
	}

	return ""
}

// extractArgInfo counts arguments and checks for string concatenation.
func (ap *ASTParser) extractArgInfo(node *sitter.Node, source []byte) (count int, hasConcat bool, argText string) {
	// Look for argument list child
	var argNode *sitter.Node
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		switch child.Type() {
		case "arguments", "argument_list", "actual_parameters", "token_tree":
			argNode = child
		}
	}
	if argNode == nil {
		if args := node.ChildByFieldName("arguments"); args != nil {
			argNode = args
		}
	}

	if argNode == nil {
		return 0, false, ""
	}

	argText = nodeText(argNode, source)

	// Count arguments and check structure
	for i := 0; i < int(argNode.ChildCount()); i++ {
		child := argNode.Child(i)
		if child == nil {
			continue
		}
		t := child.Type()
		if t != "," && t != "(" && t != ")" {
			count++
		}
		// Check for string concatenation patterns
		if t == "binary_expression" || t == "concatenated_string" ||
			t == "string_concat" || t == "string_content" {
			hasConcat = true
		}
	}

	// Also check arg text for + operator or f-strings
	if !hasConcat {
		hasConcat = containsConcatPattern(argText)
	}

	return count, hasConcat, argText
}

// extractContext walks up the AST to determine surrounding context.
func (ap *ASTParser) extractContext(node *sitter.Node, source []byte, candidate *CandidateNode) {
	current := node.Parent()
	for current != nil {
		parentType := current.Type()

		switch parentType {
		case "comment", "line_comment", "block_comment":
			candidate.IsInComment = true

		case "try_statement", "try_expression", "catch_clause",
			"except_clause", "rescue":
			candidate.IsInTryCatch = true

		case "if_statement", "if_expression", "conditional_expression",
			"switch_statement", "match_expression", "guard":
			candidate.IsInConditional = true

		case "for_statement", "while_statement", "for_expression",
			"do_statement", "loop_expression", "foreach_statement":
			candidate.IsInLoop = true

		case "function_definition", "function_declaration",
			"method_declaration", "method_definition",
			"function_item", "arrow_function":
			funcName := ""
			if nameNode := current.ChildByFieldName("name"); nameNode != nil {
				funcName = nodeText(nameNode, source)
			}
			if funcName != "" {
				candidate.ParentFunctionName = funcName
				candidate.IsPublicFunction = isExportedName(funcName, ap.language)
			}
		}

		current = current.Parent()
	}
}

// containsConcatPattern checks raw text for string concatenation patterns.
func containsConcatPattern(text string) bool {
	// Check for f-strings (Python)
	if strings.Contains(text, "f\"") || strings.Contains(text, "f'") {
		return true
	}
	// Check for template literals (JS/TS)
	if strings.Contains(text, "${") {
		return true
	}

	inString := false
	prevChar := byte(0)
	for i := 0; i < len(text); i++ {
		ch := text[i]
		if ch == '"' || ch == '\'' {
			if prevChar != '\\' {
				inString = !inString
			}
		}
		if !inString && ch == '+' {
			return true
		}
		prevChar = ch
	}
	return false
}

// isExportedName checks if a function name is public/exported.
func isExportedName(name string, lang Language) bool {
	if name == "" {
		return false
	}
	switch lang {
	case LanguageGo:
		return name[0] >= 'A' && name[0] <= 'Z'
	case LanguagePython:
		return name[0] != '_'
	default:
		return true
	}
}

// nodeText returns the source text of an AST node.
func nodeText(node *sitter.Node, source []byte) string {
	if node == nil {
		return ""
	}
	start := node.StartByte()
	end := node.EndByte()
	if int(start) >= len(source) || int(end) > len(source) || start > end {
		return ""
	}
	return string(source[start:end])
}
