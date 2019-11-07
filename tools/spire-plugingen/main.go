package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
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
	outFlag := fs.String("out", "", "package to output, defaults to current package if blank")
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

	packagePath := args[0]
	serviceNames := args[1:]
	mode := strings.ToLower(*modeFlag)

	g := generator{
		Package:      *packageFlag,
		PackagePath:  packagePath,
		ServiceNames: serviceNames,
		Out:          *outFlag,
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

	// PackagePath is the path to the go package containing the services.
	PackagePath string

	// Name of the services in the package.
	ServiceNames []string

	// Out is the directory to output to. Uses working directory if unset.
	Out string

	// Mode determines the kind of code to generate.
	Mode string

	// Shared is set if the output package is intended to hold multiple
	// plugins/services/hostservices. It forces service prefixes onto
	// each generated declaration.
	Shared bool

	outPkg *types.Package
}

func (g *generator) generate() (err error) {
	switch g.Mode {
	case pluginMode, serviceMode, hostServiceMode:
	default:
		return errs.New("invalid mode")
	}

	if g.Out == "" {
		g.Out, err = os.Getwd()
		if err != nil {
			return errs.Wrap(err)
		}
	}

	var pkg *types.Package
	outPkg, err := loadPackage(g.Out, true)
	if err == nil {
		if g.Package == "" {
			g.Package = outPkg.Name()
		}
		if outPkg.Path() == g.PackagePath {
			pkg = outPkg
		}
		g.outPkg = outPkg
	} else {
		if g.Package == "" {
			g.Package = filepath.Base(g.Out)
		}
	}
	if pkg == nil {
		pkg, err = loadPackage(g.PackagePath, true)
		if err != nil {
			return errs.Wrap(err)
		}
	}

	typeImports := map[goImport]bool{}
	var clients []serviceClient
	for _, serviceName := range g.ServiceNames {
		serverName := serviceName + "Server"
		serverObj := pkg.Scope().Lookup(serverName)
		if serverObj == nil {
			return errs.New("package %q does not have a type %q", pkg.Name(), serverName)
		}
		_, serverType := g.getTypeFromObj(serverObj)
		if _, ok := serverObj.Type().Underlying().(*types.Interface); !ok {
			return errs.New("%s is not an interface", serverType)
		}

		clientName := serviceName + "Client"
		clientObj := pkg.Scope().Lookup(clientName)
		if clientObj == nil {
			return errs.New("package %q does not have a type %q", pkg.Name(), clientName)
		}
		_, clientType := g.getTypeFromObj(clientObj)
		clientIntf, ok := clientObj.Type().Underlying().(*types.Interface)
		if !ok {
			return errs.New("%s is not an interface", clientType)
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

				typeImport, typeName := g.getType(param.Type())
				typeImports[typeImport] = true
				params = append(params, serviceParam{
					Name: param.Name(),
					Type: typeName,
				})
			}

			var results []serviceParam
			for i := 0; i < sig.Results().Len(); i++ {
				result := sig.Results().At(i)

				typeImport, typeName := g.getType(result.Type())
				typeImports[typeImport] = true
				results = append(results, serviceParam{
					Name: result.Name(),
					Type: typeName,
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

		pkgQual := fmt.Sprintf("%s.", pkg.Name())
		if g.outPkg != nil && pkg.Path() == g.outPkg.Path() {
			pkgQual = ""
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

	imports := []goImport{
		{Path: "github.com/spiffe/spire/pkg/common/catalog"},
		{Path: "google.golang.org/grpc"},
	}
	for typeImport := range typeImports {
		if typeImport.Path != "" {
			imports = append(imports, typeImport)
		}
	}

	if err := os.MkdirAll(g.Out, 0755); err != nil {
		return errs.New("unable to create output directory: %v", err)
	}
	for _, client := range clients {
		out := new(bytes.Buffer)
		if err := tmpl.Execute(out, map[string]interface{}{
			"Package": g.Package,
			"Imports": imports,
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

		if err := ioutil.WriteFile(filepath.Join(g.Out, strings.ToLower(client.Name)+".go"), outBytes, 0644); err != nil {
			return errs.New("unable to write generated code for %s: %v", client.Name, err)
		}
	}
	return nil
}

func (g *generator) getType(typ types.Type) (goImport, string) {
	switch t := typ.(type) {
	case *types.Named:
		return g.getTypeFromObj(t.Obj())
	case *types.Pointer:
		i, n := g.getType(t.Elem())
		return i, "*" + n
	case *types.Struct:
		return g.getType(t.Underlying())
	default:
		panic(fmt.Sprintf("unhandled type %T", typ))
	}
}

func (g *generator) getTypeFromObj(obj types.Object) (goImport, string) {
	pkg := obj.Pkg()
	switch {
	case pkg == nil:
		return goImport{}, obj.Name()
	case g.outPkg != nil && g.outPkg.Path() == pkg.Path():
		return goImport{}, obj.Name()
	default:
		imp := goImport{
			Path: pkg.Path(),
			As:   pkgAs(pkg.Path()),
		}
		if imp.As != "" {
			return imp, fmt.Sprintf("%s.%s", imp.As, obj.Name())
		}
		return imp, fmt.Sprintf("%s.%s", obj.Pkg().Name(), obj.Name())
	}
}

func loadPackage(path string, ignoreErrors bool) (*types.Package, error) {
	pkgs, err := packages.Load(&packages.Config{
		Mode: packages.NeedTypes,
	}, path)
	if err != nil {
		return nil, errs.New("unable to load package %q: %v", path, err)
	}

	if len(pkgs) != 1 {
		return nil, errs.New("expected 1 %q package; got %d", path, len(pkgs))
	}

	pkg := pkgs[0]
	if !ignoreErrors && len(pkg.Errors) > 0 {
		return nil, errs.New("errors found loading package %q: %q", path, pkg.Errors)
	}

	return pkg.Types, nil
}

func pkgAs(path string) string {
	switch path {
	case "github.com/spiffe/spire/proto/spire/common/plugin":
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
