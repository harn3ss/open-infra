package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The aws-shim half of the AWS coverage registry that probe/shimgen.py joins with the CloudFormation
// engine's half (cfn/coverage_registry_test.go): the services the router serves (the SigV4 signing names
// it dispatches on), the handler behind each, and the operations that handler dispatches. All of it is
// read from this package's own source — the services table in main.go and the handler types' methods —
// so a new front door or operation reaches the registry, and the docs rendered from it, without anyone
// writing it down. The committed probe/registry/shim-router.json must match; UPDATE_REGISTRY=1 rewrites
// it (probe/shimgen.py does that when Go is on PATH).
const shimRegistryPath = "../../../probe/registry/shim-router.json"

type shimRegistryService struct {
	Handler     string   `json:"handler"`               // the Go type that serves it
	Operations  []string `json:"operations"`            // the operation names it dispatches on and serves
	Refused     []string `json:"refused,omitempty"`     // operations it recognizes only to refuse
	Actions     []string `json:"actions,omitempty"`     // the IAM actions its per-operation authorization names
	Delegates   []string `json:"delegates,omitempty"`   // the handler types a dispatching wrapper hands requests to
	Conditional bool     `json:"conditional,omitempty"` // registered only when its backing component is configured
}

type shimRegistry struct {
	GeneratedBy string                         `json:"generatedBy"`
	Services    map[string]shimRegistryService `json:"services"`
}

var (
	// An AWS operation name is a verb, usually with a noun (CreateQueue, ReEncrypt, Publish). The verb list keeps
	// out the other CamelCase values a switch or return can carry: comparison operators
	// (GreaterThanThreshold), states, error codes.
	opNameRe = regexp.MustCompile(`^(Abort|Add|Admin|Allocate|Assume|Associate|Attach|Batch|Cancel|Change|Complete|Confirm|Copy|` +
		`Create|Deactivate|Decrease|Delete|Deregister|Describe|Detach|Detect|Disable|Disassociate|Enable|Encrypt|Decrypt|Execute|Filter|` +
		`Forgot|Generate|Get|Global|Head|Import|Increase|Initiate|Invoke|Label|List|Modify|Publish|Purge|Put|Re|Reboot|Receive|` +
		`Query|Register|Release|Remove|Request|Resend|Respond|Restore|Resync|Rotate|Run|Scan|Schedule|Send|Set|Sign|Signal|Simulate|Start|Stop|` +
		`Subscribe|Tag|Terminate|Test|Transact|Unsubscribe|Untag|Update|Upload|Validate|Verify)([A-Z0-9][A-Za-z0-9]*)?$`)
	// refuseCallRe names a call that answers an error, and refuseTextRe the words of a refusal: a case whose
	// body is nothing but such calls (and returns), saying the operation is not supported, recognizes its
	// operations only to refuse them (case "CreateDBInstanceReadReplica": writeQueryError(…, "read
	// replicas are not supported…")), so they are refused, not served. An error that is an answer — a
	// ResourceNotFoundException, a log group that already exists — is not a refusal.
	refuseCallRe = regexp.MustCompile(`(?i)^write\w*error$|^refuse|unsupported|notimplemented`)
	refuseTextRe = regexp.MustCompile(`(?i)not (supported|implemented)|unsupported|operator concern|does not fire`)
	iamActionRe  = regexp.MustCompile(`^[a-z0-9-]+:[A-Z][A-Za-z0-9]+$`) // sqs:SendMessage
	kebabOpRe    = regexp.MustCompile(`^[a-z]+(-[a-z0-9]+)*$`)          // list-buckets (S3's decoded kind)
	dispatchTags = map[string]bool{"op": true, "action": true, "operation": true, "verb": true}
)

// shimSource is the package's non-test Go source, parsed and indexed.
type shimSource struct {
	files     []*ast.File
	funcs     map[string]*ast.FuncDecl   // package-level functions
	methods   map[string][]*ast.FuncDecl // receiver type -> its methods
	paramFns  map[string][]*ast.FuncDecl // type -> the package functions that take it (or a pointer to it)
	structs   map[string]*ast.StructType
	serveable map[string]bool // types with a serve method (the awsService shape)
}

func parseShimSource(t *testing.T) *shimSource {
	t.Helper()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	src := &shimSource{funcs: map[string]*ast.FuncDecl{}, methods: map[string][]*ast.FuncDecl{},
		paramFns: map[string][]*ast.FuncDecl{}, structs: map[string]*ast.StructType{}, serveable: map[string]bool{}}
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", p, err)
		}
		src.files = append(src.files, f)
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv != nil && len(d.Recv.List) == 1 {
					rt := typeName(d.Recv.List[0].Type)
					src.methods[rt] = append(src.methods[rt], d)
					if d.Name.Name == "serve" {
						src.serveable[rt] = true
					}
					continue
				}
				src.funcs[d.Name.Name] = d
				if d.Type.Params != nil {
					for _, fld := range d.Type.Params.List {
						if n := typeName(fld.Type); n != "" {
							src.paramFns[n] = append(src.paramFns[n], d)
						}
					}
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					if ts, ok := s.(*ast.TypeSpec); ok {
						if st, ok := ts.Type.(*ast.StructType); ok {
							src.structs[ts.Name.Name] = st
						}
					}
				}
			}
		}
	}
	return src
}

// typeName is the named type an expression spells (T or *T), or "".
func typeName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return typeName(e.X)
	}
	return ""
}

// scope is a function body's local definitions: name -> the expressions (or declared types) bound to it.
type scope map[string][]ast.Expr

func localDefs(body *ast.BlockStmt) scope {
	sc := scope{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if len(n.Lhs) == len(n.Rhs) {
				for i, l := range n.Lhs {
					if id, ok := l.(*ast.Ident); ok {
						sc[id.Name] = append(sc[id.Name], n.Rhs[i])
					}
				}
			} else if len(n.Rhs) == 1 {
				// h, err := newH(...): the handler is the first result
				if id, ok := n.Lhs[0].(*ast.Ident); ok {
					sc[id.Name] = append(sc[id.Name], n.Rhs[0])
				}
			}
		case *ast.ValueSpec:
			for i, id := range n.Names {
				if n.Type != nil {
					sc[id.Name] = append(sc[id.Name], n.Type)
				}
				if i < len(n.Values) {
					sc[id.Name] = append(sc[id.Name], n.Values[i])
				}
			}
		}
		return true
	})
	return sc
}

// resolve finds the handler type an expression in the services table evaluates to.
func (s *shimSource) resolve(e ast.Expr, sc scope, depth int) string {
	if depth > 8 {
		return ""
	}
	switch e := e.(type) {
	case *ast.UnaryExpr:
		return s.resolve(e.X, sc, depth+1)
	case *ast.CompositeLit:
		return typeName(e.Type)
	case *ast.StarExpr:
		return typeName(e.X)
	case *ast.CallExpr:
		if id, ok := e.Fun.(*ast.Ident); ok {
			if fd := s.funcs[id.Name]; fd != nil && fd.Type.Results != nil && len(fd.Type.Results.List) > 0 {
				return typeName(fd.Type.Results.List[0].Type)
			}
		}
	case *ast.Ident:
		if _, isStruct := s.structs[e.Name]; isStruct {
			return e.Name // a declared type (var h *T)
		}
		for _, def := range sc[e.Name] {
			if n := s.resolve(def, sc, depth+1); n != "" && n != "awsService" {
				return n
			}
		}
	}
	return ""
}

// reachable is a handler type's code: its methods, the package functions that take it, and every package
// function those call, transitively (a handler's dispatch is often a helper: a route decoder, a verb
// switch). Methods of other types are not followed, so one handler's operations are not another's.
func (s *shimSource) reachable(typ string) []*ast.FuncDecl {
	var out []*ast.FuncDecl
	seen := map[*ast.FuncDecl]bool{}
	queue := append(append([]*ast.FuncDecl{}, s.methods[typ]...), s.paramFns[typ]...)
	for len(queue) > 0 {
		fd := queue[0]
		queue = queue[1:]
		if seen[fd] || fd.Body == nil {
			continue
		}
		seen[fd] = true
		out = append(out, fd)
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok {
					if callee := s.funcs[id.Name]; callee != nil && !seen[callee] {
						queue = append(queue, callee)
					}
				}
			}
			return true
		})
	}
	return out
}

// identName is the name an identifier or selector spells (eksRefused, x.Refused), or "".
func identName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

var refusedMarkRe = regexp.MustCompile(`(?i)refused|unsupported|notimplemented`)

// dispatch collects the operation names a handler type's code dispatches on, the ones it recognizes only
// to refuse, and the IAM actions it authorizes by name.
func (s *shimSource) dispatch(typ string) (ops, refused, actions map[string]bool) {
	ops, refused, actions = map[string]bool{}, map[string]bool{}, map[string]bool{}
	defer func() {
		for k := range refused {
			delete(ops, k)
		}
	}()
	for _, fd := range s.reachable(typ) {
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.SwitchStmt:
				kebab := isKindTag(n.Tag)
				if !kebab && !isDispatchTag(n.Tag) {
					return true
				}
				for _, st := range n.Body.List {
					cc, ok := st.(*ast.CaseClause)
					if !ok {
						continue
					}
					refusing := refusalOnly(cc.Body)
					for _, v := range cc.List {
						lit, ok := v.(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						name, err := strconv.Unquote(lit.Value)
						if err != nil {
							continue
						}
						if kebab {
							if kebabOpRe.MatchString(name) {
								name = kebabToOp(name)
							} else {
								continue
							}
						} else if !opNameRe.MatchString(name) {
							continue
						}
						if refusing {
							refused[name] = true
						} else {
							ops[name] = true
						}
					}
				}
			case *ast.ReturnStmt:
				// a route decoder that returns the operation it recognized: return p, "GetResolver", nil
				for _, r := range n.Results {
					if lit, ok := r.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if v, err := strconv.Unquote(lit.Value); err == nil && opNameRe.MatchString(v) {
							ops[v] = true
						}
					}
				}
			case *ast.CompositeLit:
				// a route decoder that builds the operation it recognized: restV1Op{Op: "GetRestApi", …}. One
				// it marks refused (eksRequest{op: "CreateCluster", cat: eksRefused}) is recognized, not served.
				var name string
				isRefused := false
				for _, el := range n.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if k, ok := kv.Key.(*ast.Ident); ok && dispatchTags[strings.ToLower(k.Name)] {
						if lit, ok := kv.Value.(*ast.BasicLit); ok && lit.Kind == token.STRING {
							if v, err := strconv.Unquote(lit.Value); err == nil && opNameRe.MatchString(v) {
								name = v
							}
						}
					} else if refusedMarkRe.MatchString(identName(kv.Value)) {
						isRefused = true
					}
				}
				if name != "" {
					if isRefused {
						refused[name] = true
					} else {
						ops[name] = true
					}
				}
			case *ast.BasicLit:
				if n.Kind == token.STRING {
					if v, err := strconv.Unquote(n.Value); err == nil && iamActionRe.MatchString(v) {
						actions[v] = true
					}
				}
			}
			return true
		})
	}
	return ops, refused, actions
}

// refusalOnly reports whether a case body does nothing but answer a refusal (and return): error calls
// whose text says the operation is not supported.
func refusalOnly(body []ast.Stmt) bool {
	calls := 0
	refusal := false
	for _, st := range body {
		switch st := st.(type) {
		case *ast.ReturnStmt:
		case *ast.ExprStmt:
			call, ok := st.X.(*ast.CallExpr)
			if !ok || !refuseCallRe.MatchString(identName(call.Fun)) {
				return false
			}
			calls++
			ast.Inspect(call, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if v, err := strconv.Unquote(lit.Value); err == nil && refuseTextRe.MatchString(v) {
						refusal = true
					}
				}
				return true
			})
		default:
			return false
		}
	}
	return calls > 0 && refusal
}

func isDispatchTag(e ast.Expr) bool {
	switch e := e.(type) {
	case *ast.Ident:
		return dispatchTags[e.Name]
	case *ast.SelectorExpr:
		return dispatchTags[e.Sel.Name]
	}
	return false
}

// isKindTag: S3 decodes a request into an s3op whose kind is the operation in the CLI's spelling
// (list-buckets, head-bucket; a bare verb — get, put, head, delete — is the object operation).
func isKindTag(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "kind"
}

func kebabToOp(k string) string {
	parts := strings.Split(k, "-")
	if len(parts) == 1 {
		parts = append(parts, "object")
	}
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(strings.ToUpper(p[:1]) + p[1:])
	}
	return b.String()
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func buildShimRegistry(t *testing.T) shimRegistry {
	src := parseShimSource(t)
	reg := shimRegistry{GeneratedBy: "console-api/cmd/aws-shim/coverage_registry_test.go", Services: map[string]shimRegistryService{}}
	add := func(key string, val ast.Expr, sc scope, conditional bool) {
		h := src.resolve(val, sc, 0)
		svc := shimRegistryService{Handler: h, Conditional: conditional}
		ops, refused, actions := src.dispatch(h)
		// A dispatching wrapper — a struct whose every field is another handler (API Gateway's v1/v2 mux) —
		// serves its delegates' operations. A handler that merely holds another (the CloudFormation doorway
		// holds the REST v1 store it provisions through) does not: those are not its operations.
		if st := src.structs[h]; st != nil && len(st.Fields.List) > 0 {
			var delegates []string
			for _, fld := range st.Fields.List {
				if d := typeName(fld.Type); src.serveable[d] {
					delegates = append(delegates, d)
				} else {
					delegates = nil
					break
				}
			}
			for _, d := range delegates {
				svc.Delegates = append(svc.Delegates, d)
				o, r, a := src.dispatch(d)
				for k := range o {
					ops[k] = true
				}
				for k := range r {
					refused[k] = true
				}
				for k := range a {
					actions[k] = true
				}
			}
		}
		for k := range refused {
			delete(ops, k)
		}
		svc.Operations, svc.Refused, svc.Actions = sortedKeys(ops), sortedKeys(refused), sortedKeys(actions)
		if prev, dup := reg.Services[key]; dup && prev.Handler != h {
			t.Errorf("service %q is registered with two handlers (%s, %s)", key, prev.Handler, h)
		}
		reg.Services[key] = svc
	}
	// visit finds the services table and every services["x"] = h registration in a function body; one
	// made inside an if (a component that may be off) is conditional.
	var visit func(n ast.Node, sc scope, cond bool)
	visit = func(n ast.Node, sc scope, cond bool) {
		ast.Inspect(n, func(c ast.Node) bool {
			switch c := c.(type) {
			case *ast.IfStmt:
				if c.Init != nil {
					visit(c.Init, sc, cond)
				}
				visit(c.Body, sc, true)
				if c.Else != nil {
					visit(c.Else, sc, true)
				}
				return false
			case *ast.AssignStmt:
				if len(c.Lhs) != 1 || len(c.Rhs) != 1 {
					return true
				}
				if id, ok := c.Lhs[0].(*ast.Ident); ok && id.Name == "services" {
					if cl, ok := c.Rhs[0].(*ast.CompositeLit); ok {
						if mt, ok := cl.Type.(*ast.MapType); ok && typeName(mt.Value) == "awsService" {
							for _, el := range cl.Elts {
								if kv, ok := el.(*ast.KeyValueExpr); ok {
									if lit, ok := kv.Key.(*ast.BasicLit); ok && lit.Kind == token.STRING {
										k, _ := strconv.Unquote(lit.Value)
										add(k, kv.Value, sc, cond)
									}
								}
							}
						}
					}
				}
				if ix, ok := c.Lhs[0].(*ast.IndexExpr); ok {
					if id, ok := ix.X.(*ast.Ident); ok && id.Name == "services" {
						if lit, ok := ix.Index.(*ast.BasicLit); ok && lit.Kind == token.STRING {
							k, _ := strconv.Unquote(lit.Value)
							add(k, c.Rhs[0], sc, cond)
						}
					}
				}
			}
			return true
		})
	}
	for _, f := range src.files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				visit(fd.Body, localDefs(fd.Body), false)
			}
		}
	}
	return reg
}

func TestCoverageRegistryShimRouter(t *testing.T) {
	reg := buildShimRegistry(t)
	if len(reg.Services) < 10 {
		t.Fatalf("found only %d services in the router table — the services map in main.go was not recognized", len(reg.Services))
	}
	for k, s := range reg.Services {
		if s.Handler == "" {
			t.Errorf("service %q: could not resolve the handler type its registration names", k)
		}
	}
	got, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if os.Getenv("UPDATE_REGISTRY") != "" {
		if err := os.WriteFile(shimRegistryPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(shimRegistryPath)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("probe/registry/shim-router.json is stale (the shim's services or operations changed): run "+
			"probe/shimgen.py (or UPDATE_REGISTRY=1 go test ./cmd/aws-shim -run TestCoverageRegistry) and commit "+
			"the result (read error: %v)", err)
	}
}

// The registry tells served operations from refused ones (#401): an operation a handler recognizes only to
// refuse, explicitly or by its route decoder, is listed as refused and never as served, and an error that is
// an answer (a function with no policy, a log group that already exists) leaves its operation served.
func TestCoverageRegistry_ServedIsNotRefused(t *testing.T) {
	reg := buildShimRegistry(t)
	has := func(list []string, op string) bool {
		for _, o := range list {
			if o == op {
				return true
			}
		}
		return false
	}
	for _, c := range []struct {
		svc, op string
		served  bool
	}{
		{"ec2", "RebootInstances", true}, {"ec2", "TerminateInstances", true}, {"ec2", "ImportKeyPair", true},
		{"cloudformation", "SignalResource", true},
		{"rds", "AddTagsToResource", false}, {"rds", "ListTagsForResource", false}, {"rds", "CreateDBInstanceReadReplica", false},
		{"eks", "AssociateIdentityProviderConfig", false}, {"eks", "CreateCluster", false},
		{"secretsmanager", "RotateSecret", false},
		{"lambda", "GetPolicy", true}, {"logs", "CreateLogGroup", true}, {"logs", "StartQuery", false},
	} {
		svc, ok := reg.Services[c.svc]
		if !ok {
			t.Fatalf("no service %s in the registry", c.svc)
		}
		if got := has(svc.Operations, c.op); got != c.served {
			t.Errorf("%s %s: served=%v, want %v", c.svc, c.op, got, c.served)
		}
		if got := has(svc.Refused, c.op); got == c.served {
			t.Errorf("%s %s: refused=%v, want %v", c.svc, c.op, got, !c.served)
		}
	}
}
