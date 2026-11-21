// Agent A — Go AST extractor (stdlib only).
//
// Parses every .go file under a directory, type-checks each package best-effort
// (go/types) to resolve method RECEIVER TYPES, and emits a normalized IR as JSON
// for the Python call-graph builder + taint engine.
//
// Emits a node for EVERY function AND every function literal (closure), so the
// call graph can connect func-value calls too. Usage:  go run . <dir>
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
)

type Param struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Variadic bool   `json:"variadic,omitempty"`
}

type Expr struct {
	Idents []string    `json:"idents"`
	Concat bool        `json:"concat"`
	StrLit bool        `json:"strlit"`
	Calls  []*CallExpr `json:"calls,omitempty"`
	Anon   string      `json:"anon,omitempty"` // key of a func-literal value here
}

type CallExpr struct {
	Callee   string  `json:"callee"`
	Recv     string  `json:"recv,omitempty"`
	RecvType string  `json:"recvType,omitempty"`
	Full     string  `json:"full"`
	Args     []*Expr `json:"args"`
	Line     int     `json:"line"`
}

type Op struct {
	Op     string    `json:"op"`
	Line   int       `json:"line"`
	Lhs    []string  `json:"lhs,omitempty"`
	Rhs    *Expr     `json:"rhs,omitempty"`
	Call   *CallExpr `json:"call,omitempty"`
	Values []*Expr   `json:"values,omitempty"`
}

type Func struct {
	Key        string   `json:"key"`
	Name       string   `json:"name"`
	RecvType   string   `json:"recvType,omitempty"`
	Params     []Param  `json:"params"`
	ParamNames []string `json:"paramNames"`
	Results    []string `json:"results,omitempty"`
	Pkg        string   `json:"pkg"`
	Pos        string   `json:"pos"`
	Anon       bool     `json:"anonymous,omitempty"`
	Ops        []*Op    `json:"ops"`
}

type Out struct {
	Dir       string  `json:"dir"`
	Functions []*Func `json:"functions"`
	CallSeen  int     `json:"call_seen"`  // CallExprs turned into IR (via callInfo)
	CallTotal int     `json:"call_total"` // CallExprs present in function bodies
}

var callSeen int

var (
	fset        = token.NewFileSet()
	typeInfo    *types.Info
	funcStack   []string        // enclosing function keys (for anon naming)
	anonCount   = map[string]int{}
	pendingAnon []*Func         // func-literals discovered while building a function
	keyCount    = map[string]int{} // for unique keys (init collisions, dup names)
)

func uniqueKey(base string) string {
	n := keyCount[base]
	keyCount[base]++
	if n == 0 {
		return base
	}
	return fmt.Sprintf("%s#%d", base, n)
}

func line(p token.Pos) int { return fset.Position(p).Line }

func curParent() string {
	if len(funcStack) == 0 {
		return "?"
	}
	return funcStack[len(funcStack)-1]
}

func baseTypeName(t types.Type) string {
	if t == nil {
		return ""
	}
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := t.(*types.Named); ok {
		return n.Obj().Name()
	}
	return ""
}

func exprText(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return exprText(x.X) + "." + x.Sel.Name
	case *ast.StarExpr:
		return "*" + exprText(x.X)
	case *ast.ArrayType:
		return "[]" + exprText(x.Elt)
	case *ast.MapType:
		return "map[" + exprText(x.Key) + "]" + exprText(x.Value)
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.FuncType:
		return "func"
	case *ast.CallExpr:
		return exprText(x.Fun) + "()"
	case *ast.Ellipsis:
		return "..." + exprText(x.Elt)
	default:
		return "expr"
	}
}

func paramsOf(fl *ast.FieldList) ([]Param, []string) {
	var ps []Param
	var names []string
	if fl == nil {
		return ps, names
	}
	for _, p := range fl.List {
		_, variadic := p.Type.(*ast.Ellipsis)
		typ := exprText(p.Type)
		if len(p.Names) == 0 {
			ps = append(ps, Param{Type: typ, Variadic: variadic})
		}
		for _, n := range p.Names {
			ps = append(ps, Param{Name: n.Name, Type: typ, Variadic: variadic})
			names = append(names, n.Name)
		}
	}
	return ps, names
}

func exprInfo(e ast.Expr) *Expr {
	info := &Expr{}
	seen := map[string]bool{}
	add := func(n string) {
		if n == "" || n == "_" || seen[n] {
			return
		}
		seen[n] = true
		info.Idents = append(info.Idents, n)
	}
	var walk func(ast.Expr)
	walk = func(ex ast.Expr) {
		switch x := ex.(type) {
		case *ast.Ident:
			add(x.Name)
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				info.StrLit = true
			}
		case *ast.BinaryExpr:
			if x.Op == token.ADD {
				info.Concat = true
			}
			walk(x.X)
			walk(x.Y)
		case *ast.ParenExpr:
			walk(x.X)
		case *ast.StarExpr:
			walk(x.X)
		case *ast.UnaryExpr:
			walk(x.X)
		case *ast.IndexExpr:
			walk(x.X)
			walk(x.Index)
		case *ast.SliceExpr:
			walk(x.X)
		case *ast.SelectorExpr:
			walk(x.X)
		case *ast.CallExpr:
			info.Calls = append(info.Calls, callInfo(x))
			// capture calls on the RECEIVER side of a chained call, e.g. the
			// Query() in r.URL.Query().Get(...) or getRepo() in getRepo().Do().
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				walk(sel.X)
			}
		case *ast.FuncLit:
			info.Anon = buildAnon(x) // emit a node for the closure
		case *ast.CompositeLit:
			for _, el := range x.Elts {
				walk(el)
			}
		case *ast.KeyValueExpr:
			walk(x.Value)
		case *ast.TypeAssertExpr:
			walk(x.X)
		}
	}
	walk(e)
	return info
}

func buildAnon(fl *ast.FuncLit) string {
	parent := curParent()
	anonCount[parent]++
	key := uniqueKey(fmt.Sprintf("%s$func%d", parent, anonCount[parent]))
	ps, names := paramsOf(fl.Type.Params)
	af := &Func{Key: key, Name: key, Pkg: "", Anon: true,
		Pos: fset.Position(fl.Pos()).String(), Params: ps, ParamNames: names}
	funcStack = append(funcStack, key)
	af.Ops = buildOps(fl.Body)
	funcStack = funcStack[:len(funcStack)-1]
	pendingAnon = append(pendingAnon, af)
	return key
}

func callInfo(c *ast.CallExpr) *CallExpr {
	callSeen++
	ci := &CallExpr{Line: line(c.Pos())}
	switch fn := c.Fun.(type) {
	case *ast.Ident:
		ci.Callee, ci.Full = fn.Name, fn.Name
	case *ast.SelectorExpr:
		ci.Callee = fn.Sel.Name
		if id, ok := fn.X.(*ast.Ident); ok {
			ci.Recv = id.Name
			ci.Full = id.Name + "." + fn.Sel.Name
		} else {
			ci.Full = exprText(fn.X) + "." + fn.Sel.Name
		}
		if typeInfo != nil {
			ci.RecvType = baseTypeName(typeInfo.TypeOf(fn.X))
		}
	case *ast.FuncLit:
		key := buildAnon(fn) // IIFE: func(){ ... }()
		ci.Callee, ci.Full = key, key
	default:
		ci.Full = "?"
	}
	for _, a := range c.Args {
		ci.Args = append(ci.Args, exprInfo(a))
	}
	return ci
}

func identNames(e ast.Expr) []string {
	switch x := e.(type) {
	case *ast.Ident:
		return []string{x.Name}
	case *ast.SelectorExpr:
		if id, ok := x.X.(*ast.Ident); ok {
			return []string{id.Name}
		}
	}
	return nil
}

// buildOps uses an EXPLICIT statement walker (not ast.Inspect) so that calls in
// EVERY position are captured — if/for conditions, switch tags, case bodies,
// select, channel sends, var declarations — and func-literals are turned into
// their own nodes exactly once (no double counting).
func buildOps(body *ast.BlockStmt) []*Op {
	ops := []*Op{} // never nil, so JSON is [] not null (empty-body funcs)
	if body == nil {
		return ops
	}
	emitAssign := func(lhs []string, rhsExprs []ast.Expr, pos token.Pos) {
		op := &Op{Op: "assign", Line: line(pos), Lhs: lhs}
		merged := &Expr{}
		ms := map[string]bool{}
		for _, r := range rhsExprs {
			ei := exprInfo(r)
			merged.Concat = merged.Concat || ei.Concat
			merged.StrLit = merged.StrLit || ei.StrLit
			merged.Calls = append(merged.Calls, ei.Calls...)
			if ei.Anon != "" {
				merged.Anon = ei.Anon
			}
			for _, id := range ei.Idents {
				if !ms[id] {
					ms[id] = true
					merged.Idents = append(merged.Idents, id)
				}
			}
		}
		op.Rhs = merged
		ops = append(ops, op)
	}
	emitExpr := func(e ast.Expr) { // capture calls/taint in a bare expression
		if e == nil {
			return
		}
		ops = append(ops, &Op{Op: "expr", Line: line(e.Pos()), Rhs: exprInfo(e)})
	}

	var walk func(s ast.Stmt)
	walkList := func(ss []ast.Stmt) {
		for _, s := range ss {
			walk(s)
		}
	}
	walk = func(s ast.Stmt) {
		switch x := s.(type) {
		case nil:
		case *ast.AssignStmt:
			var lhs []string
			for _, l := range x.Lhs {
				lhs = append(lhs, identNames(l)...)
			}
			emitAssign(lhs, x.Rhs, x.Pos())
		case *ast.ExprStmt:
			// route through exprInfo so chained receiver calls like a().b() are
			// captured too (callInfo alone drops the receiver-side call).
			emitExpr(x.X)
		case *ast.DeclStmt:
			if gd, ok := x.Decl.(*ast.GenDecl); ok {
				for _, spec := range gd.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok && len(vs.Values) > 0 {
						var lhs []string
						for _, n := range vs.Names {
							if n.Name != "_" {
								lhs = append(lhs, n.Name)
							}
						}
						emitAssign(lhs, vs.Values, vs.Pos())
					}
				}
			}
		case *ast.ReturnStmt:
			op := &Op{Op: "return", Line: line(x.Pos())}
			for _, r := range x.Results {
				op.Values = append(op.Values, exprInfo(r))
			}
			ops = append(ops, op)
		case *ast.RangeStmt:
			var lhs []string
			lhs = append(lhs, identNames(x.Key)...)
			lhs = append(lhs, identNames(x.Value)...)
			emitAssign(lhs, []ast.Expr{x.X}, x.Pos())
			walk(x.Body)
		case *ast.SendStmt: // ch <- value
			emitAssign(identNames(x.Chan), []ast.Expr{x.Value}, x.Pos())
		case *ast.IncDecStmt:
			emitExpr(x.X)
		case *ast.GoStmt:
			emitExpr(x.Call) // captures receiver chain + IIFE closures
		case *ast.DeferStmt:
			emitExpr(x.Call)
		case *ast.IfStmt:
			walk(x.Init)
			emitExpr(x.Cond)
			walk(x.Body)
			walk(x.Else)
		case *ast.ForStmt:
			walk(x.Init)
			emitExpr(x.Cond)
			walk(x.Post)
			walk(x.Body)
		case *ast.SwitchStmt:
			walk(x.Init)
			emitExpr(x.Tag)
			walk(x.Body)
		case *ast.TypeSwitchStmt:
			walk(x.Init)
			walk(x.Assign)
			walk(x.Body)
		case *ast.SelectStmt:
			walk(x.Body)
		case *ast.CommClause:
			walk(x.Comm)
			walkList(x.Body)
		case *ast.CaseClause:
			for _, e := range x.List {
				emitExpr(e)
			}
			walkList(x.Body)
		case *ast.BlockStmt:
			walkList(x.List)
		case *ast.LabeledStmt:
			walk(x.Stmt)
		case *ast.BranchStmt, *ast.EmptyStmt:
		}
	}
	walk(body)
	return ops
}

func buildFunc(fd *ast.FuncDecl, pkg string) *Func {
	f := &Func{Name: fd.Name.Name, Pkg: pkg, Pos: fset.Position(fd.Pos()).String()}
	prefix := pkg + "."
	if pkg == "" {
		prefix = ""
	}
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		f.RecvType = strings.TrimPrefix(exprText(fd.Recv.List[0].Type), "*")
		f.Key = uniqueKey(prefix + f.RecvType + "." + f.Name)
	} else {
		f.Key = uniqueKey(prefix + f.Name)
	}
	f.Params, f.ParamNames = paramsOf(fd.Type.Params)
	if fd.Type.Results != nil {
		for _, r := range fd.Type.Results.List {
			n := len(r.Names)
			if n == 0 {
				n = 1
			}
			for i := 0; i < n; i++ {
				f.Results = append(f.Results, exprText(r.Type))
			}
		}
	}
	funcStack = append(funcStack, f.Key)
	f.Ops = buildOps(fd.Body)
	funcStack = funcStack[:len(funcStack)-1]
	return f
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go_extract <dir>")
		os.Exit(2)
	}
	root := os.Args[1]
	out := &Out{Dir: root}

	byDir := map[string][]string{}
	filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if fi.IsDir() {
			name := fi.Name()
			if name == "vendor" || (strings.HasPrefix(name, ".") && len(name) > 1) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			d := filepath.Dir(path)
			byDir[d] = append(byDir[d], path)
		}
		return nil
	})

	for dir, paths := range byDir {
		var files []*ast.File
		pkgName := ""
		for _, p := range paths {
			fa, perr := parser.ParseFile(fset, p, nil, 0)
			if perr != nil {
				fmt.Fprintf(os.Stderr, "parse warn %s: %v\n", p, perr)
				continue
			}
			files = append(files, fa)
			if pkgName == "" {
				pkgName = fa.Name.Name
			}
		}
		info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{},
			Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
		conf := types.Config{Importer: importer.Default(), Error: func(error) {}}
		conf.Check(dir, fset, files, info)
		typeInfo = info

		for _, fa := range files {
			for _, decl := range fa.Decls {
				if fd, ok := decl.(*ast.FuncDecl); ok {
					if fd.Body != nil {
						ast.Inspect(fd.Body, func(n ast.Node) bool {
							if _, ok := n.(*ast.CallExpr); ok {
								out.CallTotal++
							}
							return true
						})
					}
					pendingAnon = nil
					fn := buildFunc(fd, pkgName)
					out.Functions = append(out.Functions, fn)
					for _, af := range pendingAnon { // attach closures of this func
						af.Pkg = pkgName
						out.Functions = append(out.Functions, af)
					}
				}
			}
		}
		typeInfo = nil
	}

	out.CallSeen = callSeen
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
