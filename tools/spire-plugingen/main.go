package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"go/token"
	"go/types"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"unicode"

	"github.com/zeebo/errs"
	"golang.org/x/tools/go/packages"
	goimports "golang.org/x/tools/imports"
)

const (
	pluginMode      = "plugin"
	serviceMode     = "service"
	hostServiceMode = "hostservice"
)

var (
	funcs = template.FuncMap{
		"mkexpname": mkexpname,
		"mkname":    mkname,
	}
	tmpl = template.Must(template.New("").Funcs(funcs).Parse(codeTmpl))
)

func main() {
	fs := flag.NewFlagSet("spire-plugin-gen", flag.ExitOnError)
	packageFlag := fs.String("package", "", "package to output, defaults to current package if blank")
	outFlag := fs.String("out", "", "directory to write output, defaults to current directory if blank")
	modeFlag := fs.String("mode", "plugin", `generation mode (one of "plugin", "service", "hostservice")`)
	sharedFlag := fs.Bool("shared", false, `output package is a shared package (forces prefix on generated code)`)
	if err := fs.Parse(os.Args[1:]); err != nil {
		fs.Usage()
		os.Exit(1)
	}

	args := fs.Args()
	if len(args) < 2 {
		fs.Usage()
		os.Exit(1)
	}

	packageDir := args[0]
	serviceNames := args[1:]
	mode := strings.ToLower(*modeFlag)

	g := generator{
		Package:      *packageFlag,
		PackageDir:   packageDir,
		ServiceNames: serviceNames,
		OutDir:       *outFlag,
		Mode:         mode,
		Shared:       *sharedFlag,
	}

	if err := g.generate(); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}

type goImport struct {
	As   string
	Path string
}

type goAlias struct {
	Name string
	Type string
}

type goConst struct {
	Name  string
	Value string
}

type serviceParam struct {
	Name string
	Type string
}

type serviceMethod struct {
	Name       string
	Params     []serviceParam
	Results    []serviceParam
	PluginOnly bool
}

type serviceClient struct {
	PkgQual    string
	Name       string
	Prefix     string
	ClientType string
	ServerType string
	Methods    []serviceMethod
}

type generator struct {
	// Package to output to. If blank, uses directory name of output directory.
	Package string

	// PackageDir is the path to the go package containing the services.
	PackageDir string

	// Name of the services in the package.
	ServiceNames []string

	// OutDir is the directory to output to. Uses working directory if unset.
	OutDir string

	// Mode determines the kind of code to generate.
	Mode string

	// Shared is set if the output package is intended to hold multiple
	// plugins/services/hostservices. It forces service prefixes onto
	// each generated declaration.
	Shared bool

	pkg      *types.Package
	needQual bool
}

func (g *generator) generate() (err error) {
	switch g.Mode {
	case pluginMode, serviceMode, hostServiceMode:
	default:
		return errs.New("invalid mode")
	}

	outDir := g.OutDir
	if outDir == "" {
		outDir, err = os.Getwd()
		if err != nil {
			return errs.Wrap(err)
		}
	}

	outDir, err = filepath.Abs(outDir)
	if err != nil {
		return errs.Wrap(err)
	}

	packageDir, err := filepath.Abs(g.PackageDir)
	if err != nil {
		return errs.Wrap(err)
	}

	if outDir != packageDir {
		g.needQual = true
	}

	pkg, fset, err := loadPackage(packageDir)
	if err != nil {
		return err
	}
	g.pkg = pkg
	switch {
	case !g.needQual:
		g.Package = pkg.Name()
	case g.Package == "":
		g.Package = filepath.Base(outDir)
	}

	typeImports := map[goImport]bool{}
	var clients []serviceClient
	var sourceFile string
	for _, serviceName := range g.ServiceNames {
		serverName := serviceName + "Server"
		serverObj := pkg.Scope().Lookup(serverName)
		if serverObj == nil {
			return errs.New("package %q does not have a type %q", pkg.Name(), serverName)
		}
		sourceFile = fset.Position(serverObj.Pos()).Filename
		serverType, serverImp := g.getTypeFromObj(serverObj)
		if _, ok := serverObj.Type().Underlying().(*types.Interface); !ok {
			return errs.New("%s is not an interface", serverType)
		}
		if serverImp != nil {
			typeImports[*serverImp] = true
		}

		clientName := serviceName + "Client"
		clientObj := pkg.Scope().Lookup(clientName)
		if clientObj == nil {
			return errs.New("package %q does not have a type %q", pkg.Name(), clientName)
		}

		clientType, clientImp := g.getTypeFromObj(clientObj)
		clientIntf, ok := clientObj.Type().Underlying().(*types.Interface)
		if !ok {
			return errs.New("%s is not an interface", clientType)
		}
		if clientImp != nil {
			typeImports[*clientImp] = true
		}

		var methods []serviceMethod
		for i := 0; i < clientIntf.NumMethods(); i++ {
			m := clientIntf.Method(i)

			sig := m.Type().(*types.Signature)

			var params []serviceParam
			// don't do the last param, since that is the call options that
			// we want to drop
			for i := 0; i < sig.Params().Len()-1; i++ {
				param := sig.Params().At(i)

				typ, imp := g.getType(param.Type())
				if imp != nil {
					typeImports[*imp] = true
				}
				params = append(params, serviceParam{
					Name: param.Name(),
					Type: typ,
				})
			}

			var results []serviceParam
			for i := 0; i < sig.Results().Len(); i++ {
				result := sig.Results().At(i)

				typ, imp := g.getType(result.Type())
				if imp != nil {
					typeImports[*imp] = true
				}
				results = append(results, serviceParam{
					Name: result.Name(),
					Type: typ,
				})
			}

			methodName := m.Name()
			methods = append(methods, serviceMethod{
				Name:       methodName,
				Params:     params,
				Results:    results,
				PluginOnly: methodName == "Configure" || methodName == "GetPluginInfo",
			})
		}

		var pkgQual string
		if g.needQual {
			pkgQual = fmt.Sprintf("%s.", pkg.Name())
		}

		prefix := serviceName
		if !g.Shared && len(g.ServiceNames) == 1 {
			// there is only one gRPC service definition in this package. don't
			// prefix generated funcs/types.
			prefix = ""
		}

		clients = append(clients, serviceClient{
			PkgQual:    pkgQual,
			Name:       serviceName,
			Prefix:     prefix,
			ClientType: clientType,
			ServerType: serverType,
			Methods:    methods,
		})
	}

	// Alias types and add consts from the file that the server/client
	// interfaces came from
	var aliases []goAlias
	var consts []goConst
	if g.needQual {
		for _, name := range pkg.Scope().Names() {
			obj := pkg.Scope().Lookup(name)
			if fset.Position(obj.Pos()).Filename != sourceFile {
				continue
			}
			if !obj.Exported() {
				continue
			}
			switch obj.(type) {
			case *types.Const:
				consts = append(consts, goConst{
					Name:  obj.Name(),
					Value: pkg.Name() + "." + obj.Name(),
				})
			case *types.TypeName:
				aliases = append(aliases, goAlias{
					Name: obj.Name(),
					Type: pkg.Name() + "." + obj.Name(),
				})
			}
		}
	}

	imports := []goImport{
		{Path: "github.com/spiffe/spire/pkg/common/catalog"},
		{Path: "google.golang.org/grpc"},
	}
	for typeImport := range typeImports {
		if typeImport.Path != "" {
			imports = append(imports, typeImport)
		}
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		return errs.New("unable to create output directory: %v", err)
	}
	for _, client := range clients {
		out := new(bytes.Buffer)
		if err := tmpl.Execute(out, map[string]interface{}{
			"Package": g.Package,
			"Imports": imports,
			"Consts":  consts,
			"Aliases": aliases,
			"Client":  client,
			"Mode":    g.Mode,
		}); err != nil {
			return errs.Wrap(err)
		}
		outBytes, err := goimports.Process("", out.Bytes(), nil)
		if err != nil {
			dumpLined(os.Stderr, out)
			return errs.Wrap(err)
		}

		if err := ioutil.WriteFile(filepath.Join(outDir, strings.ToLower(client.Name)+".go"), outBytes, 0644); err != nil {
			return errs.New("unable to write generated code for %s: %v", client.Name, err)
		}
	}
	return nil
}

func (g *generator) getType(typ types.Type) (string, *goImport) {
	switch t := typ.(type) {
	case *types.Named:
		return g.getTypeFromObj(t.Obj())
	case *types.Pointer:
		n, i := g.getType(t.Elem())
		return "*" + n, i
	case *types.Struct:
		return g.getType(t.Underlying())
	default:
		panic(fmt.Sprintf("unhandled type %T", typ))
	}
}

func (g *generator) getTypeFromObj(obj types.Object) (string, *goImport) {
	pkg := obj.Pkg()
	switch {
	case pkg == nil:
		return obj.Name(), nil
	case g.pkg.Path() == pkg.Path() && !g.needQual:
		return obj.Name(), nil
	default:
		pkgQual := obj.Pkg().Name()
		as := pkgAs(pkg.Path())
		if as != "" {
			pkgQual = as
		}

		imp := &goImport{
			Path: pkg.Path(),
			As:   as,
		}

		if pkg.Path() == g.pkg.Path() {
			// type will be aliased into this package
			pkgQual = ""
		}

		typeName := obj.Name()
		if pkgQual != "" {
			typeName = pkgQual + "." + typeName
		}
		return typeName, imp
	}
}

func loadPackage(path string) (*types.Package, *token.FileSet, error) {
	fset := token.NewFileSet()
	pkgs, err := packages.Load(&packages.Config{
		Fset: fset,
		Dir:  path,
		Mode: packages.NeedTypes | packages.NeedImports,
	}, ".")
	if err != nil {
		return nil, nil, errs.New("unable to load package %q: %v", path, err)
	}

	if len(pkgs) != 1 {
		return nil, nil, errs.New("expected 1 %q package; got %d", path, len(pkgs))
	}

	pkg := pkgs[0]
	if len(pkg.Errors) > 0 {
		return nil, nil, errs.New("errors found loading package %q: %q", path, pkg.Errors)
	}

	return pkg.Types, fset, nil
}

func pkgAs(path string) string {
	if path == "github.com/spiffe/spire/proto/spire/common/plugin" {
		return "spi"
	}
	return ""
}

func dumpLined(w io.Writer, r io.Reader) {
	line := 1
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fmt.Fprintf(w, "%5d: %s\n", line, scanner.Text())
		line++
	}
}

func mkexpname(parts ...string) string {
	return strings.Join(parts, "")
}

func mkname(parts ...string) string {
	s := mkexpname(parts...)
	if len(s) == 0 {
		return s
	}
	rs := []rune(s)
	rs[0] = unicode.ToLower(rs[0])
	return string(rs)
}
