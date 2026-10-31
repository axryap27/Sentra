package engine

import (
	"context"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// Candidate is an AST node that might be a security-relevant site.
type Candidate struct {
	Name      string // function/method name or assigned identifier
	Line      int    // 1-based line
	Column    int    // 1-based column (bytes)
	EndLine   int
	EndColumn int
	NodeType  string // tree-sitter node type, e.g. "call_expression"

	ArgCount           int
	HasStringConcatArg bool
	ParentFunctionName string
	IsInComment        bool
	IsInTryCatch       bool
	IsInConditional    bool
	IsInLoop           bool
	IsPublicFunction   bool
	NodeDepth          int
	RawLine            string // the source line, for pattern features
	ArgSource          string // raw text of the argument list
	AssignedIdentifier string // assignments: left-hand side
	AssignedValue      string // assignments: right-hand side
}

// scope is the context inherited from a node's ancestors. It is maintained as a
// stack during the depth-first walk, so no per-candidate Parent() walk is needed
// (ts_node_parent is O(depth) in tree-sitter).
type scope struct {
	inComment, inTry, inCond, inLoop bool
	fnName                           string
	fnPublic                         bool
}

type walker struct {
	lang       Language
	kinds      []nodeKind
	src        []byte
	lineStarts []int
	sc         scope
	out        []Candidate
}

// parseCandidates parses source with p and returns candidate nodes.
func parseCandidates(p *sitter.Parser, lang Language, kinds []nodeKind, src []byte) []Candidate {
	tree, err := p.ParseCtx(context.Background(), nil, src)
	if err != nil || tree == nil {
		return nil
	}
	defer tree.Close()
	root := tree.RootNode()
	if root == nil {
		return nil
	}

	w := &walker{lang: lang, kinds: kinds, src: src, lineStarts: lineIndex(src)}
	cur := sitter.NewTreeCursor(root)
	defer cur.Close()
	w.visit(cur, 0)
	return w.out
}

// visit walks the subtree under the cursor. A TreeCursor is used instead of
// node.Child(i): ts_node_child(i) scans siblings from the start, which makes
// iterating a wide node (e.g. a module with thousands of statements) quadratic.
// Nodes are classified by numeric symbol through a per-language table, so the
// hot loop does not allocate a Go string for every node's type.
func (w *walker) visit(cur *sitter.TreeCursor, depth int) {
	n := cur.CurrentNode()
	var kind nodeKind
	if sym := int(n.Symbol()); sym < len(w.kinds) { // ERROR nodes use symbol 65535
		kind = w.kinds[sym]
	}

	if kind&kindCandidate != 0 {
		w.inspect(n, kind, depth)
	}

	saved := w.sc
	if kind&kindScope != 0 {
		w.enter(n, kind)
	}
	if cur.GoToFirstChild() {
		for {
			w.visit(cur, depth+1)
			if !cur.GoToNextSibling() {
				break
			}
		}
		cur.GoToParent()
	}
	w.sc = saved
}

// enter updates the scope for n's descendants.
func (w *walker) enter(n *sitter.Node, kind nodeKind) {
	switch {
	case kind&kindComment != 0:
		w.sc.inComment = true
	case kind&kindTry != 0:
		w.sc.inTry = true
	case kind&kindCond != 0:
		w.sc.inCond = true
	case kind&kindLoop != 0:
		w.sc.inLoop = true
	case kind&kindFunc != 0:
		if w.sc.fnName == "" { // outermost enclosing function, as before
			if name := n.ChildByFieldName("name"); name != nil {
				if fn := w.text(name); fn != "" {
					w.sc.fnName = fn
					w.sc.fnPublic = isExportedName(fn, w.lang)
				}
			}
		}
	}
}

// inspect emits a candidate if n is a call, assignment or relevant keyword argument.
func (w *walker) inspect(n *sitter.Node, kind nodeKind, depth int) {
	var c *Candidate
	switch {
	case kind&kindCall != 0:
		c = w.callCandidate(n)
	case kind&kindAssign != 0:
		c = w.assignmentCandidate(n)
	case kind&kindKeywordArg != 0:
		c = w.keywordArgCandidate(n)
	}
	if c == nil {
		return
	}
	start, end := n.StartPoint(), n.EndPoint()
	c.Line = int(start.Row) + 1
	c.Column = int(start.Column) + 1
	c.EndLine = int(end.Row) + 1
	c.EndColumn = int(end.Column) + 1
	c.NodeType = n.Type()
	c.NodeDepth = depth
	c.RawLine = w.lineWindow(int(start.Row), int(n.StartByte()))
	c.ParentFunctionName = w.sc.fnName
	c.IsPublicFunction = w.sc.fnPublic
	c.IsInComment = w.sc.inComment
	c.IsInTryCatch = w.sc.inTry
	c.IsInConditional = w.sc.inCond
	c.IsInLoop = w.sc.inLoop
	w.out = append(w.out, *c)
}

// nodeKind classifies a tree-sitter symbol for the walker.
type nodeKind uint8

const (
	kindCall nodeKind = 1 << iota
	kindAssign
	kindKeywordArg
	kindComment
	kindTry
	kindCond
	kindLoop
	kindFunc

	kindCandidate = kindCall | kindAssign | kindKeywordArg
	kindScope     = kindComment | kindTry | kindCond | kindLoop | kindFunc
)

func kindOf(typ string) nodeKind {
	switch {
	case isCallNode(typ):
		return kindCall
	case isAssignmentNode(typ):
		return kindAssign
	case typ == "keyword_argument":
		return kindKeywordArg
	}
	switch typ {
	case "comment", "line_comment", "block_comment":
		return kindComment
	case "try_statement", "try_expression", "catch_clause", "except_clause", "rescue":
		return kindTry
	case "if_statement", "if_expression", "conditional_expression",
		"switch_statement", "match_expression", "guard":
		return kindCond
	case "for_statement", "while_statement", "for_expression",
		"do_statement", "loop_expression", "foreach_statement":
		return kindLoop
	case "function_definition", "function_declaration", "method_declaration",
		"method_definition", "function_item", "arrow_function":
		return kindFunc
	}
	return 0
}

// kindTable maps every symbol of a grammar to its nodeKind.
func kindTable(g *sitter.Language) []nodeKind {
	n := g.SymbolCount()
	t := make([]nodeKind, n+1)
	for s := uint32(0); s < n; s++ {
		t[s] = kindOf(g.SymbolName(sitter.Symbol(s)))
	}
	return t
}

func isCallNode(t string) bool {
	switch t {
	case "call_expression", "call", "invocation_expression",
		"method_invocation", "function_call_expression", "macro_invocation",
		"object_creation_expression", "new_expression":
		return true
	}
	return false
}

func isAssignmentNode(t string) bool {
	switch t {
	case "assignment", "assignment_expression", "variable_declaration",
		"variable_declarator", "let_declaration", "short_var_declaration",
		"augmented_assignment":
		return true
	}
	return false
}

func (w *walker) callCandidate(n *sitter.Node) *Candidate {
	name := w.functionName(n)
	if name == "" {
		return nil
	}
	c := &Candidate{Name: name}
	c.ArgCount, c.HasStringConcatArg, c.ArgSource = w.argInfo(n)
	return c
}

func (w *walker) assignmentCandidate(n *sitter.Node) *Candidate {
	var ident, value string
	if left := n.ChildByFieldName("left"); left != nil {
		ident = w.clipped(left, maxNameText, true)
	}
	if right := n.ChildByFieldName("right"); right != nil {
		value = w.clipped(right, maxArgText, false)
	}
	if ident == "" {
		for i := 0; i < int(n.ChildCount()); i++ {
			child := n.Child(i)
			if child == nil {
				continue
			}
			switch child.Type() {
			case "identifier", "property_identifier", "field_identifier", "member_expression", "attribute":
				if ident == "" {
					ident = w.clipped(child, maxNameText, true)
				}
			case "string", "string_literal", "template_string", "raw_string_literal",
				"interpreted_string_literal", "encapsed_string":
				if value == "" {
					value = w.clipped(child, maxArgText, false)
				}
			}
		}
	}
	if ident == "" {
		return nil
	}
	return &Candidate{Name: ident, AssignedIdentifier: ident, AssignedValue: value}
}

func (w *walker) keywordArgCandidate(n *sitter.Node) *Candidate {
	text := w.clipped(n, maxArgText, false)
	if !strings.Contains(text, "shell") || !strings.Contains(text, "True") {
		return nil
	}
	return &Candidate{Name: "shell=True"}
}

// functionName returns the callee name of a call node.
func (w *walker) functionName(n *sitter.Node) string {
	if fn := n.ChildByFieldName("function"); fn != nil {
		return w.clipped(fn, maxNameText, true)
	}
	// Java method_invocation: object.name, e.g. "Runtime.getRuntime().exec".
	if name := n.ChildByFieldName("name"); name != nil {
		if obj := n.ChildByFieldName("object"); obj != nil {
			return w.clipped(obj, maxNameText, true) + "." + w.text(name)
		}
		return w.text(name)
	}
	if m := n.ChildByFieldName("method"); m != nil {
		return w.text(m)
	}
	if t := n.ChildByFieldName("type"); t != nil { // constructors
		return w.text(t)
	}
	for i := 0; i < int(n.ChildCount()); i++ {
		child := n.Child(i)
		if child == nil {
			continue
		}
		switch child.Type() {
		case "identifier", "member_expression", "attribute", "field_expression",
			"scoped_identifier", "qualified_name", "member_access_expression",
			"type_identifier", "generic_type":
			return w.clipped(child, maxNameText, true)
		}
	}
	return ""
}

// argInfo counts arguments and detects string building in them.
func (w *walker) argInfo(n *sitter.Node) (count int, concat bool, text string) {
	var args *sitter.Node
	for i := 0; i < int(n.ChildCount()); i++ {
		child := n.Child(i)
		if child == nil {
			continue
		}
		switch child.Type() {
		case "arguments", "argument_list", "actual_parameters", "token_tree":
			args = child
		}
	}
	if args == nil {
		args = n.ChildByFieldName("arguments")
	}
	if args == nil {
		return 0, false, ""
	}
	text = w.clipped(args, maxArgText, false)
	for i := 0; i < int(args.ChildCount()); i++ {
		child := args.Child(i)
		if child == nil {
			continue
		}
		t := child.Type()
		if t != "," && t != "(" && t != ")" {
			count++
		}
		if t == "binary_expression" || t == "concatenated_string" || t == "string_concat" || t == "string_content" {
			concat = true
		}
	}
	if !concat {
		concat = containsConcatPattern(text)
	}
	return count, concat, text
}

func (w *walker) text(n *sitter.Node) string {
	if n == nil {
		return ""
	}
	start, end := int(n.StartByte()), int(n.EndByte())
	if start > end || end > len(w.src) {
		return ""
	}
	return string(w.src[start:end])
}

// lineIndex returns the byte offset at which each line starts.
func lineIndex(src []byte) []int {
	starts := make([]int, 1, len(src)/32+1)
	for i, b := range src {
		if b == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

// Limits on text copied into a Candidate. Without them a minified file (one
// 100 KB+ line) made every candidate copy and lowercase the whole file, which
// is quadratic: one 163 KB file took ~10 s. Ordinary code is far below these.
const (
	lineWindow  = 400  // bytes kept on each side of the node within its line
	maxArgText  = 2048 // bytes of argument / assigned-value text kept
	maxNameText = 256  // bytes of callee text kept (the tail, where the method name is)
)

// lineWindow returns the node's source line, clipped to lineWindow bytes on
// either side of offset.
func (w *walker) lineWindow(row, offset int) string {
	if row < 0 || row >= len(w.lineStarts) {
		return ""
	}
	start := w.lineStarts[row]
	end := len(w.src)
	if row+1 < len(w.lineStarts) {
		end = w.lineStarts[row+1] - 1 // drop '\n'
	}
	if offset-start > lineWindow {
		start = offset - lineWindow
	}
	if end-offset > lineWindow {
		end = offset + lineWindow
	}
	return string(w.src[start:end])
}

// clipped returns the node text truncated to limit bytes, keeping the head
// (tail=false) or the tail (tail=true).
func (w *walker) clipped(n *sitter.Node, limit int, tail bool) string {
	if n == nil {
		return ""
	}
	start, end := int(n.StartByte()), int(n.EndByte())
	if start > end || end > len(w.src) {
		return ""
	}
	if end-start > limit {
		if tail {
			start = end - limit
		} else {
			end = start + limit
		}
	}
	return string(w.src[start:end])
}

// containsConcatPattern checks raw text for string concatenation/interpolation.
func containsConcatPattern(text string) bool {
	if strings.Contains(text, "f\"") || strings.Contains(text, "f'") || strings.Contains(text, "${") {
		return true
	}
	inString := false
	var prev byte
	for i := 0; i < len(text); i++ {
		ch := text[i]
		if (ch == '"' || ch == '\'') && prev != '\\' {
			inString = !inString
		}
		if !inString && ch == '+' {
			return true
		}
		prev = ch
	}
	return false
}

// isExportedName reports whether a function name is public/exported.
func isExportedName(name string, lang Language) bool {
	if name == "" {
		return false
	}
	switch lang {
	case Go:
		return name[0] >= 'A' && name[0] <= 'Z'
	case Python:
		return name[0] != '_'
	default:
		return true
	}
}
