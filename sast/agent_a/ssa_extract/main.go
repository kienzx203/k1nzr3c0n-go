// Agent A — SSA/VTA call-graph extractor (precise, hybrid engine "A").
//
// When the target Go project BUILDS (resolvable modules), this uses
// go/packages + go/ssa + callgraph/vta (over an initial CHA graph) to compute a
// SOUND call graph that resolves interface dispatch, closures, func-values,
// method values, generics and cross-package user calls — exactly the cases the
// AST heuristic misses.
//
// It emits, for each resolved call SITE, the precise callee identity so the
// Python side can OVERRIDE the AST resolver (matched by call-site file:line and
// callee identity). If loading fails (code doesn't build), it prints
// {"ok":false,...} and the pipeline falls back to the AST engine.
//
// Usage:  go run . <dir>
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

type Edge struct {
	SiteFile   string `json:"site_file"`
	SiteLine   int    `json:"site_line"`
	CalleeName string `json:"callee_name"`
	CalleePkg  string `json:"callee_pkg"`
	CalleeRecv string `json:"callee_recv"`
	CalleePos  string `json:"callee_pos"`
	CallerPos  string `json:"caller_pos"`
	Dynamic    bool   `json:"dynamic"`
}

type Out struct {
	OK        bool     `json:"ok"`
	Algorithm string   `json:"algorithm,omitempty"`
	Error     string   `json:"error,omitempty"`
	Partial   bool     `json:"partial,omitempty"` // some packages had build errors
	Packages  []string `json:"packages,omitempty"`
	Edges     []Edge   `json:"edges,omitempty"`
}

func fail(msg string) {
	json.NewEncoder(os.Stdout).Encode(Out{OK: false, Error: msg})
}

func main() {
	if len(os.Args) < 2 {
		fail("usage: ssa_extract <dir>")
		return
	}
	dir := os.Args[1]
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedDeps |
			packages.NeedImports | packages.NeedModule,
		Dir: dir, Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		fail("packages.Load: " + err.Error())
		return
	}
	if len(pkgs) == 0 {
		fail("no packages loaded (project may not build)")
		return
	}
	// user package paths = loaded packages that actually have source files and a
	// real import path (reject ad-hoc "command-line-arguments" / pattern loads,
	// which indicate a missing/invalid go.mod and would silently drop all edges).
	userPaths := map[string]bool{}
	var names []string
	partial := false
	for _, p := range pkgs {
		if len(p.Errors) > 0 {
			partial = true
		}
		if p.PkgPath == "" || p.PkgPath == "command-line-arguments" ||
			strings.Contains(p.PkgPath, "...") {
			continue
		}
		if len(p.GoFiles) == 0 && len(p.CompiledGoFiles) == 0 {
			continue
		}
		userPaths[p.PkgPath] = true
		names = append(names, p.PkgPath)
	}
	if len(userPaths) == 0 {
		fail("could not resolve module packages (missing/invalid go.mod?)")
		return
	}

	prog, _ := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	func() {
		defer func() { recover() }() // tolerate partial programs
		prog.Build()
	}()

	allFuncs := ssautil.AllFunctions(prog)
	var cg *callgraph.Graph
	algo := "vta"
	chaCG := cha.CallGraph(prog)
	func() {
		defer func() {
			if r := recover(); r != nil {
				cg, algo = chaCG, "cha"
			}
		}()
		cg = vta.CallGraph(allFuncs, chaCG)
	}()
	if cg == nil {
		cg, algo = chaCG, "cha"
	}

	fs := prog.Fset
	out := Out{OK: true, Algorithm: algo, Packages: names, Partial: partial}
	seen := map[string]bool{}
	for fn, node := range cg.Nodes {
		if fn == nil || fn.Pkg == nil || !userPaths[fn.Pkg.Pkg.Path()] {
			continue // only edges FROM user code
		}
		for _, e := range node.Out {
			if e.Site == nil || e.Callee == nil || e.Callee.Func == nil {
				continue
			}
			cf := e.Callee.Func
			if cf.Pkg == nil || !userPaths[cf.Pkg.Pkg.Path()] {
				continue // only edges TO user code (stdlib handled by spec)
			}
			if !cf.Pos().IsValid() {
				continue
			}
			sitePos := fs.Position(e.Site.Pos())
			calleePos := fs.Position(cf.Pos())
			recv := ""
			if sig := cf.Signature; sig != nil && sig.Recv() != nil {
				recv = baseName(sig.Recv().Type().String())
			}
			dynamic := e.Site.Common().StaticCallee() == nil
			key := fmt.Sprintf("%s:%d>%s", sitePos.Filename, sitePos.Line, calleePos.String())
			if seen[key] {
				continue
			}
			seen[key] = true
			out.Edges = append(out.Edges, Edge{
				SiteFile: sitePos.Filename, SiteLine: sitePos.Line,
				CalleeName: cf.Name(), CalleePkg: cf.Pkg.Pkg.Name(),
				CalleeRecv: recv, CalleePos: calleePos.String(),
				CallerPos: fs.Position(fn.Pos()).String(), Dynamic: dynamic,
			})
		}
	}
	json.NewEncoder(os.Stdout).Encode(out)
}

// baseName strips package path and pointer from a receiver type string like
// "*example.com/xpkg/store.Repo" -> "Repo".
func baseName(s string) string {
	for len(s) > 0 && (s[0] == '*' || s[0] == '(') {
		s = s[1:]
	}
	if i := lastDotOutsideBrackets(s); i >= 0 {
		s = s[i+1:]
	}
	for i := 0; i < len(s); i++ {
		if s[i] == ')' || s[i] == '[' {
			return s[:i]
		}
	}
	return s
}

func lastDotOutsideBrackets(s string) int {
	depth, last := 0, -1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[':
			depth++
		case ']':
			depth--
		case '.':
			if depth == 0 {
				last = i
			}
		}
	}
	return last
}
