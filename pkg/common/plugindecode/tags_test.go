package plugindecode_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const (
	repoRoot   = "../../.."
	modulePath = "github.com/spiffe/spire"
)

// yamlOptOut lists HCL options that are deliberately not YAML keys, with the
// reason. Keys are "<package path>.<struct>.<field>".
var yamlOptOut = map[string]string{
	"pkg/server/plugin/nodeattestor/awsiid.IIDAttestorConfig.AssumeRole": "copied from the embedded SessionConfig",
	"pkg/server/plugin/nodeattestor/awsiid.IIDAttestorConfig.Partition":  "copied from the embedded SessionConfig",
}

// TestYAMLTags requires every struct field that HCL decodes to carry the
// matching yaml tag, named like its HCL key. Structs without
// hcl tags are checked too when a decoded field refers to them.
func TestYAMLTags(t *testing.T) {
	structs := parseStructs(t, "pkg", "cmd/spire-server", "cmd/spire-agent")

	var queue []*structInfo
	for _, s := range structs {
		if s.hasHCLTag() {
			queue = append(queue, s)
		}
	}
	checked := make(map[*structInfo]bool)
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		if checked[s] {
			continue
		}
		checked[s] = true
		for _, f := range s.node.Fields.List {
			if !checkField(t, s, f) {
				continue
			}
			for _, name := range referencedTypes(s, f.Type) {
				if ref, ok := structs[name]; ok {
					queue = append(queue, ref)
				}
			}
		}
	}
}

// checkField reports a missing or wrong yaml tag, and returns whether the
// field is decoded from YAML.
func checkField(t *testing.T, s *structInfo, f *ast.Field) bool {
	tag := fieldTag(f)
	got, hasYAML := tag.Lookup("yaml")
	hcl, hasHCL := tag.Lookup("hcl")
	pos := s.fset.Position(f.Pos())

	if !hasHCL {
		if !isExported(f) {
			return false
		}
		if !hasYAML {
			if s.hasHCLTag() {
				t.Errorf("%s: field has no hcl tag; add a yaml tag (yaml:\"-\" if not configurable)", pos)
			} else {
				t.Errorf("%s: field of %s, which is decoded from HCL, has no hcl or yaml tag", pos, s.name)
			}
			return false
		}
		return got != "-"
	}

	name, opts, _ := strings.Cut(hcl, ",")
	var want string
	switch {
	case name == "-":
		// YAML-only fields, decoded by hand-written YAML types.
		return false
	case isASTNode(f.Type):
		want = "-"
	case name == "" && opts == "squash":
		want = ",inline"
	case name == "":
		want = "-"
	default:
		want = name
	}

	if got == "-" && want != "-" {
		if _, ok := yamlOptOut[s.name+"."+fieldName(f)]; ok {
			return false
		}
	}
	if got != want {
		t.Errorf("%s: want yaml:%q, got yaml:%q", pos, want, got)
	}
	return want != "-"
}

type structInfo struct {
	name    string // "<package path>.<type>"
	pkg     string
	node    *ast.StructType
	fset    *token.FileSet
	imports map[string]string // import name to package path, relative to the module
}

func (s *structInfo) hasHCLTag() bool {
	for _, f := range s.node.Fields.List {
		if _, ok := fieldTag(f).Lookup("hcl"); ok {
			return true
		}
	}
	return false
}

func parseStructs(t *testing.T, dirs ...string) map[string]*structInfo {
	structs := make(map[string]*structInfo)
	fset := token.NewFileSet()
	for _, dir := range dirs {
		err := filepath.WalkDir(filepath.Join(repoRoot, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			file, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(repoRoot, filepath.Dir(p))
			if err != nil {
				return err
			}
			pkg := filepath.ToSlash(rel)
			imports := make(map[string]string)
			for _, imp := range file.Imports {
				importPath, _ := strconv.Unquote(imp.Path.Value)
				local, ok := strings.CutPrefix(importPath, modulePath+"/")
				if !ok {
					continue
				}
				name := path.Base(local)
				if imp.Name != nil {
					name = imp.Name.Name
				}
				imports[name] = local
			}
			for _, decl := range file.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok {
					continue
				}
				for _, spec := range gen.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					if st, ok := ts.Type.(*ast.StructType); ok {
						name := pkg + "." + ts.Name.Name
						structs[name] = &structInfo{name: name, pkg: pkg, node: st, fset: fset, imports: imports}
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return structs
}

// referencedTypes returns the names of the named types that expr refers to.
func referencedTypes(s *structInfo, expr ast.Expr) []string {
	switch e := expr.(type) {
	case *ast.Ident:
		return []string{s.pkg + "." + e.Name}
	case *ast.SelectorExpr:
		if x, ok := e.X.(*ast.Ident); ok {
			if pkg, ok := s.imports[x.Name]; ok {
				return []string{pkg + "." + e.Sel.Name}
			}
		}
	case *ast.StarExpr:
		return referencedTypes(s, e.X)
	case *ast.ArrayType:
		return referencedTypes(s, e.Elt)
	case *ast.MapType:
		return referencedTypes(s, e.Value)
	}
	return nil
}

func fieldTag(f *ast.Field) reflect.StructTag {
	if f.Tag == nil {
		return ""
	}
	tag, _ := strconv.Unquote(f.Tag.Value)
	return reflect.StructTag(tag)
}

func fieldName(f *ast.Field) string {
	if len(f.Names) > 0 {
		return f.Names[0].Name
	}
	return types(f.Type)
}

func types(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return types(t.X)
	case *ast.SelectorExpr:
		return t.Sel.Name
	}
	return ""
}

func isExported(f *ast.Field) bool {
	return ast.IsExported(fieldName(f))
}

func isASTNode(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.StarExpr:
		return isASTNode(t.X)
	case *ast.ArrayType:
		return isASTNode(t.Elt)
	case *ast.SelectorExpr:
		x, ok := t.X.(*ast.Ident)
		return ok && x.Name == "ast" && t.Sel.Name == "Node"
	}
	return false
}
