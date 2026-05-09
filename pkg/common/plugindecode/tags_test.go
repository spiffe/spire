package plugindecode_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// TestYAMLTags requires every struct field that HCL decodes to carry the
// matching yaml tag: the lowerCamelCase form of its HCL key, or "-" for
// fields that are deliberately set another way in YAML.
func TestYAMLTags(t *testing.T) {
	for _, root := range []string{"../../../pkg", "../../../cmd/spire-server", "../../../cmd/spire-agent"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			checkYAMLTags(t, path)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func checkYAMLTags(t *testing.T, path string) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		st, ok := n.(*ast.StructType)
		if !ok || !hasHCLTag(st) {
			return true
		}
		for _, f := range st.Fields.List {
			want, ok := wantYAMLTag(f)
			if !ok {
				continue
			}
			got, has := fieldTag(f).Lookup("yaml")
			switch {
			case want == "" && !has:
				t.Errorf("%s: exported field has no hcl tag; add a yaml tag (yaml:\"-\" if not configurable)", fset.Position(f.Pos()))
			case want != "" && got != want && got != "-":
				t.Errorf("%s: want yaml:%q, got yaml:%q", fset.Position(f.Pos()), want, got)
			}
		}
		return true
	})
}

func hasHCLTag(st *ast.StructType) bool {
	for _, f := range st.Fields.List {
		if _, ok := fieldTag(f).Lookup("hcl"); ok {
			return true
		}
	}
	return false
}

func fieldTag(f *ast.Field) reflect.StructTag {
	if f.Tag == nil {
		return ""
	}
	tag, _ := strconv.Unquote(f.Tag.Value)
	return reflect.StructTag(tag)
}

// wantYAMLTag returns the required yaml tag, "" when any yaml tag will do, or
// ok=false when the field needs none.
func wantYAMLTag(f *ast.Field) (string, bool) {
	hcl, ok := fieldTag(f).Lookup("hcl")
	if !ok {
		for _, name := range f.Names {
			if name.IsExported() {
				return "", true
			}
		}
		return "", false
	}
	if isASTNode(f.Type) {
		return "-", true
	}
	name, opts, _ := strings.Cut(hcl, ",")
	switch {
	case name == "-":
		return "", false
	case name == "" && opts == "squash":
		return ",inline", true
	case name == "":
		return "-", true
	}
	return lowerCamel(name), true
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

func lowerCamel(s string) string {
	parts := strings.Split(s, "_")
	for i := 1; i < len(parts); i++ {
		if parts[i] != "" {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}
