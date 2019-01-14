package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"text/template"
	"unicode"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/protoc-gen-go/descriptor"
	plugin "github.com/golang/protobuf/protoc-gen-go/plugin"
)

func panice(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	reqData, err := ioutil.ReadAll(os.Stdin)
	panice(err)

	req := new(plugin.CodeGeneratorRequest)
	panice(proto.Unmarshal(reqData, req))

	// parse parameters
	options := parseOptions(req.GetParameter())

	g := NewGenerator(req, options)
	g.LearnTargets()
	g.LearnPackages()
	g.GenerateFiles()

	respData, err := proto.Marshal(g.Response())
	panice(err)

	_, err = os.Stdout.Write(respData)
	panice(err)
}

type Options struct {
	SourceRelative bool
}

func parseOptions(parameters string) Options {
	fs := flag.NewFlagSet("protoc-gen-spireplugin", flag.PanicOnError)
	pathsFlag := fs.String("paths", "import", "where to place output files: import or source_relative")
	for _, param := range strings.Split(parameters, ",") {
		parts := strings.SplitN(param, "=", 2)
		if len(parts) == 1 {
			panice(fs.Set(parts[0], ""))
			continue
		}
		panice(fs.Set(parts[0], parts[1]))
	}
	fs.Parse(nil)

	options := Options{}
	switch *pathsFlag {
	case "", "import":
	case "source_relative":
		options.SourceRelative = true
	default:
		panic(fmt.Errorf("invalid paths value %q; expected \"import\" or \"source_relative\"", *pathsFlag))
	}

	return options
}

type Generator struct {
	req     *plugin.CodeGeneratorRequest
	resp    *plugin.CodeGeneratorResponse
	options Options

	targets  map[string]bool
	imports  map[string]*ImportData
	packages map[string]*PackageData
}

func NewGenerator(req *plugin.CodeGeneratorRequest, options Options) *Generator {
	return &Generator{
		req:      req,
		resp:     new(plugin.CodeGeneratorResponse),
		options:  options,
		targets:  make(map[string]bool),
		imports:  make(map[string]*ImportData),
		packages: make(map[string]*PackageData),
	}
}

func (g *Generator) Response() *plugin.CodeGeneratorResponse {
	return g.resp
}

func (g *Generator) fail(msg string, params ...interface{}) bool {
	return g.setError(fmt.Errorf(msg, params...))
}

func (g *Generator) setError(err error) bool {
	if g.resp.Error == nil && err != nil {
		g.resp.Error = proto.String(err.Error())
	}
	return g.resp.Error != nil
}

func (g *Generator) done() bool {
	return g.resp.Error != nil
}

func (g *Generator) LearnTargets() {
	for _, targetFile := range g.req.GetFileToGenerate() {
		g.targets[targetFile] = true
	}
}

func (g *Generator) LearnPackages() {
	// TODO: cleanup
	goPkgs := make(map[string]int)
	goPkgs["context"] = 1
	for _, protoFile := range g.req.ProtoFile {
		goPkg := protoFile.GetOptions().GetGoPackage()
		count := goPkgs[goPkg]
		goPkgs[goPkg]++
		var importAs string
		if count > 1 {
			goPkg = fmt.Sprintf("%s%d", goPkg, count)
			importAs = goPkg
		}
		imp := &ImportData{
			Path: goPkg,
			As:   importAs,
		}
		g.imports[imp.Path] = imp
		g.packages[protoFile.GetPackage()] = &PackageData{
			Import:    imp,
			GoPackage: goPkg,
		}
	}
}

func (g *Generator) GenerateFiles() {
	for _, protoFile := range g.req.ProtoFile {
		// skip proto's that we're not explicitly generating
		if !g.targets[protoFile.GetName()] {
			continue
		}

		g.GenerateFile(protoFile)
		if g.done() {
			return
		}
	}
}

func (g *Generator) GenerateFile(protoFile *descriptor.FileDescriptorProto) {
	if g.done() {
		return
	}

	goPackage := protoFile.GetOptions().GetGoPackage()
	if goPackage == "" {
		goPackage = filepath.Base(filepath.Dir(protoFile.GetName()))
	}

	var dir string
	if g.options.SourceRelative {
		dir = filepath.Dir(protoFile.GetName())
	} else {
		dir = goPackage
	}

	for _, serviceDesc := range protoFile.GetService() {
		serviceData := g.BuildServiceData(protoFile, serviceDesc)
		// go_package can be a single package name or a full import path
		serviceData.Package = path.Base(goPackage)

		content, err := renderServiceData(serviceData)
		if g.setError(err) {
			return
		}

		g.resp.File = append(g.resp.File, &plugin.CodeGeneratorResponse_File{
			Name:    proto.String(fmt.Sprintf("%s/%s.go", dir, serviceData.Basename)),
			Content: proto.String(content),
		})
	}
}

type ServiceData struct {
	Package     string
	Imports     []ImportData
	Name        string
	Basename    string
	Methods     []MethodData
	UsesStreams bool
}

type ImportData struct {
	Path string
	As   string
}

type PackageData struct {
	Import    *ImportData
	GoPackage string
}

type MethodData struct {
	Name       string
	InputType  string
	OutputType string
	StreamType string
	ForPlugin  bool
}

func (g *Generator) BuildServiceData(protoFile *descriptor.FileDescriptorProto, serviceDesc *descriptor.ServiceDescriptorProto) *ServiceData {
	service := new(ServiceData)
	service.Name = serviceDesc.GetName()
	service.Basename = strings.ToLower(serviceDesc.GetName())

	importNames := make(map[string]bool)
	for _, methodDesc := range serviceDesc.GetMethod() {
		method := MethodData{
			Name: methodDesc.GetName(),
		}
		switch method.Name {
		case "Configure", "GetPluginInfo":
			method.ForPlugin = true
		}

		inputType, inputImport := g.GoType(protoFile, methodDesc.GetInputType())
		outputType, outputImport := g.GoType(protoFile, methodDesc.GetOutputType())
		importNames[inputImport] = true
		importNames[outputImport] = true

		method.InputType = inputType
		method.OutputType = outputType

		switch {
		case !methodDesc.GetClientStreaming() && !methodDesc.GetServerStreaming():
		case methodDesc.GetClientStreaming() && !methodDesc.GetServerStreaming():
			method.StreamType = "Send"
		case !methodDesc.GetClientStreaming() && methodDesc.GetServerStreaming():
			method.StreamType = "Recv"
		case methodDesc.GetClientStreaming() && methodDesc.GetServerStreaming():
			method.StreamType = "Bidi"
		}
		if method.StreamType != "" {
			service.UsesStreams = true
		}
		service.Methods = append(service.Methods, method)
	}

	// Build list of imports
	service.Imports = []ImportData{}
	for importName := range importNames {
		if importName == "" {
			continue
		}
		if imp := g.imports[importName]; imp != nil {
			service.Imports = append(service.Imports, *imp)
		}
	}

	return service
}

// GoType converts a protobuf message type t into a Go type and import path.
// If the type is local to the current file being generated (i.e. protoFile)
// then an empty import path is returned.
func (g *Generator) GoType(protoFile *descriptor.FileDescriptorProto, t string) (string, string) {
	protoPkg, protoMessage := g.parseProtoType(t)
	pkg, ok := g.packages[protoPkg]
	if !ok {
		g.fail("package not found for %q", t)
		return "", ""
	}
	if protoPkg != protoFile.GetPackage() {
		return "*" + filepath.Base(pkg.GoPackage) + "." + protoMessage, pkg.Import.Path
	} else {
		return "*" + protoMessage, ""
	}
}

// parseProtoType parses a protobuf type string into the proto package and
// message name. For example, ".foo.bar.Baz" returns ("foo.bar", "Baz").
func (g *Generator) parseProtoType(t string) (string, string) {
	parts := strings.Split(t, ".")
	if len(parts) < 2 {
		g.fail("invalid proto type %q", t)
		return "", ""
	}
	if parts[0] != "" {
		g.fail("expected leading dot in type %q", t)
	}
	return strings.Join(parts[1:len(parts)-1], "."), parts[len(parts)-1]
}

func renderServiceData(data *ServiceData) (string, error) {
	buf := new(bytes.Buffer)
	if err := serviceTmpl.Execute(buf, data); err != nil {
		return "", err
	}
	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		cmd := exec.Command("nl")
		cmd.Stdin = bytes.NewReader(buf.Bytes())
		cmd.Stdout = os.Stderr
		cmd.Run()
		return "", err
	}

	return string(formatted), nil
}

func unexportFunc(v interface{}) string {
	rs := []rune(v.(string))
	rs[0] = unicode.ToLower(rs[0])
	return string(rs)
}

var serviceTmpl = template.Must(
	template.New("").Funcs(template.FuncMap{
		"unexport": unexportFunc,
	}).Parse(`package {{ .Package }}
{{ $s := . }}

import (
	"context"
	"net/rpc"

	"github.com/golang/protobuf/ptypes/empty"
	go_plugin "github.com/hashicorp/go-plugin"
{{- if .UsesStreams }}
	"github.com/spiffe/spire/proto/builtin"
{{- end }}
	"google.golang.org/grpc"

{{- range .Imports }}
	{{ if .As }}{{ .As }} {{ end }}{{ printf "%q" .Path }}
{{- end }}
)

// {{ .Name }} is the interface used by all non-catalog components.
type {{ .Name }} interface {
{{- range .Methods }}
{{- if not .ForPlugin }}
{{- $m := . }}
{{- $streamname := printf "%s_Stream" $m.Name }}

{{- with (eq .StreamType "") }}
	{{ $m.Name }}(context.Context, {{ $m.InputType }}) ({{ $m.OutputType }}, error)
{{- end }}

{{- with (eq .StreamType "Send") }}
	{{ $m.Name }}(context.Context) ({{ $streamname }}, error)
{{- end }}

{{- with (eq .StreamType "Recv") }}
	{{ $m.Name }}(context.Context, {{ $m.InputType }}) ({{ $streamname }}, error)
{{- end }}

{{- with (eq .StreamType "Bidi") }}
	{{ $m.Name }}(context.Context) ({{ $streamname }}, error)
{{- end }}

{{- end }}
{{- end }}
}

// Plugin is the interface implemented by plugin implementations
type Plugin interface {
{{- range .Methods }}
{{- $m := . }}
{{- $streamname := printf "%s_PluginStream" $m.Name }}

{{- with (eq .StreamType "") }}
	{{ $m.Name }}(context.Context, {{ $m.InputType }}) ({{ $m.OutputType }}, error)
{{- end }}

{{- with (eq .StreamType "Send") }}
	{{ $m.Name }}({{ $streamname }}) error
{{- end }}

{{- with (eq .StreamType "Recv") }}
	{{ $m.Name }}({{ $m.InputType }}, {{ $streamname }}) error
{{- end }}

{{- with (eq .StreamType "Bidi") }}
	{{ $m.Name }}({{ $streamname }}) error
{{- end }}

{{- end }}
}

{{ range .Methods }}
{{ $m := . }}
{{ $clientintf := printf "%s_Stream" $m.Name }}
{{ $clientimpl := unexport $clientintf }}
{{ $serverintf := printf "%s_PluginStream" $m.Name }}
{{ $serverimpl := unexport $serverintf }}

{{- with (eq .StreamType "Send") }}
type {{ $clientintf }} interface {
	Context() context.Context
	Send({{ $m.InputType }}) error
	CloseAndRecv() ({{ $m.OutputType }}, error)
}

type {{ $clientimpl }} struct{
	stream builtin.SendStreamClient
}

func (s {{ $clientimpl }}) Context() context.Context {
	return s.stream.Context()
}

func (s {{ $clientimpl }}) Send(m {{ $m.InputType }}) error {
	return s.stream.Send(m)
}

func (s {{ $clientimpl }}) CloseAndRecv() ({{ $m.OutputType }}, error) {
	m, err := s.stream.CloseAndRecv()
	if err != nil {
		return nil, err
	}
	return m.({{ $m.OutputType }}), nil
}

type {{ $serverintf }} interface {
	Context() context.Context
	SendAndClose({{ $m.OutputType }}) error
	Recv() ({{ $m.InputType }}, error)
}

type {{ $serverimpl }} struct {
	stream builtin.SendStreamServer
}

func (s {{ $serverimpl }}) Context() context.Context {
	return s.stream.Context()
}

func (s {{ $serverimpl }}) SendAndClose(m {{ $m.OutputType }}) error {
	return s.stream.SendAndClose(m)
}

func (s {{ $serverimpl }}) Recv() ({{ $m.InputType }}, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.({{ $m.InputType }}), nil
}
{{- end }}

{{- with (eq .StreamType "Recv") }}
type {{ $clientintf }} interface {
	Context() context.Context
	Recv() ({{ $m.OutputType }}, error)
}

type {{ $clientimpl }} struct {
	stream builtin.RecvStreamClient
}

func (s {{ $clientimpl }}) Context() context.Context {
	return s.stream.Context()
}

func (s {{ $clientimpl }}) Recv() ({{ $m.OutputType }}, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.({{ $m.OutputType }}), nil
}

type {{ $serverintf }} interface {
	Context() context.Context
	Send({{ $m.OutputType }}) error
}

type {{ $serverimpl }} struct {
	stream builtin.RecvStreamServer
}

func (s {{ $serverimpl }}) Context() context.Context {
	return s.stream.Context()
}

func (s {{ $serverimpl }}) Send(m {{ $m.OutputType }}) error {
	return s.stream.Send(m)
}
{{- end }}

{{- with (eq .StreamType "Bidi") }}
type {{ $clientintf }} interface {
	Context() context.Context
	Send({{ $m.InputType }}) error
	Recv() ({{ $m.OutputType }}, error)
	CloseSend() error
}

type {{ $clientimpl }} struct {
	stream builtin.BidiStreamClient
}

func (s {{ $clientimpl }}) Context() context.Context {
	return s.stream.Context()
}

func (s {{ $clientimpl }}) Send(m {{ $m.InputType }}) error {
	return s.stream.Send(m)
}

func (s {{ $clientimpl }}) Recv() ({{ $m.OutputType }}, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.({{ $m.OutputType }}), nil
}

func (s {{ $clientimpl }}) CloseSend() error {
	return s.stream.CloseSend()
}

type {{ $serverintf }} interface {
	Context() context.Context
	Send({{ $m.OutputType }}) error
	Recv() ({{ $m.InputType }}, error)
}

type {{ $serverimpl }} struct {
	stream builtin.BidiStreamServer
}

func (s {{ $serverimpl }}) Context() context.Context {
	return s.stream.Context()
}

func (s {{ $serverimpl }}) Send(m {{ $m.OutputType }}) error {
	return s.stream.Send(m)
}

func (s {{ $serverimpl }}) Recv() ({{ $m.InputType }}, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.({{ $m.InputType }}), nil
}
{{- end }}

{{- end }}

type BuiltIn struct {
	plugin Plugin
}

var _ {{ .Name }} = (*BuiltIn)(nil)

func NewBuiltIn(plugin Plugin) *BuiltIn {
	return &BuiltIn{
		plugin: plugin,
	}
}

{{- range .Methods }}
{{- $m := . }}
{{ $clientintf := printf "%s_Stream" $m.Name }}
{{ $clientimpl := unexport $clientintf }}
{{ $serverintf := printf "%s_PluginStream" $m.Name }}
{{ $serverimpl := unexport $serverintf }}

{{- with (eq .StreamType "") }}
func (b BuiltIn) {{ $m.Name }}(ctx context.Context, req {{ $m.InputType }}) ({{ $m.OutputType }}, error) {
	resp, err := b.plugin.{{ $m.Name }}(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
{{- end }}

{{- with (eq .StreamType "Send") }}
func (b BuiltIn) {{ $m.Name }}(ctx context.Context) ({{ $clientintf }}, error) {
	clientStream, serverStream := builtin.{{ $m.StreamType }}StreamPipe(ctx)
	go func() {
		serverStream.Close(b.plugin.{{ $m.Name }}({{ $serverimpl }}{stream: serverStream}))
	}()
	return {{ $clientimpl }}{stream: clientStream}, nil
}
{{- end }}

{{- with (eq .StreamType "Recv") }}
func (b BuiltIn) {{ $m.Name }}(ctx context.Context, req {{ $m.InputType }}) ({{ $clientintf }}, error) {
	clientStream, serverStream := builtin.{{ $m.StreamType }}StreamPipe(ctx)
	go func() {
		serverStream.Close(b.plugin.{{ $m.Name }}(req, {{ $serverimpl }}{stream: serverStream}))
	}()
	return {{ $clientimpl }}{stream: clientStream}, nil
}
{{- end }}

{{- with (eq .StreamType "Bidi") }}
func (b BuiltIn) {{ $m.Name }}(ctx context.Context) ({{ $clientintf }}, error) {
	clientStream, serverStream := builtin.{{ $m.StreamType }}StreamPipe(ctx)
	go func() {
		serverStream.Close(b.plugin.{{ $m.Name }}({{ $serverimpl }}{stream: serverStream}))
	}()
	return {{ $clientimpl }}{stream: clientStream}, nil
}
{{- end }}

{{- end }}

var Handshake = go_plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "{{ .Name }}",
	MagicCookieValue: "{{ .Name }}",
}

type GRPCPlugin struct {
	ServerImpl {{ .Name }}Server
}

func (p GRPCPlugin) Server(*go_plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p GRPCPlugin) Client(b *go_plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p GRPCPlugin) GRPCServer(s *grpc.Server) error {
	Register{{ .Name }}Server(s, p.ServerImpl)
	return nil
}

func (p GRPCPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: New{{ .Name }}Client(c)}, nil
}

type GRPCServer struct {
	Plugin Plugin
}

{{- range .Methods }}
{{- $m := . }}
{{- $streamname := printf "%s_%sServer" $s.Name $m.Name }}

{{- with (eq .StreamType "") }}
func (s *GRPCServer) {{ $m.Name }}(ctx context.Context, req {{ $m.InputType }}) ({{ $m.OutputType }}, error) {
	return s.Plugin.{{ $m.Name }}(ctx, req)
}
{{- end }}

{{- with (eq .StreamType "Send") }}
func (s *GRPCServer) {{ $m.Name }}(stream {{ $streamname }}) error {
	return s.Plugin.{{ $m.Name }}(stream)
}
{{- end }}

{{- with (eq .StreamType "Recv") }}
func (s *GRPCServer) {{ $m.Name }}(req {{ $m.InputType }}, stream {{ $streamname }}) error {
	return s.Plugin.{{ $m.Name }}(req, stream)
}
{{- end }}

{{- with (eq .StreamType "Bidi") }}
func (s *GRPCServer) {{ $m.Name }}(stream {{ $streamname }}) error {
	return s.Plugin.{{ $m.Name }}(stream)
}
{{- end }}

{{- end }}


type GRPCClient struct {
	client {{ .Name }}Client
}

{{- range .Methods }}
{{- $m := . }}
{{- $streamname := printf "%s_Stream" $m.Name }}

{{- with (eq .StreamType "") }}
func (c *GRPCClient) {{ $m.Name }}(ctx context.Context, req {{ $m.InputType }}) ({{ $m.OutputType }}, error) {
	return c.client.{{ $m.Name }}(ctx, req)
}
{{- end }}

{{- with (eq .StreamType "Send") }}
func (c *GRPCClient) {{ $m.Name }}(ctx context.Context) ({{ $streamname }}, error) {
	return c.client.{{ $m.Name }}(ctx)
}
{{- end }}

{{- with (eq .StreamType "Recv") }}
func (c *GRPCClient) {{ $m.Name }}(ctx context.Context, req {{ $m.InputType }}) ({{ $streamname }}, error) {
	return c.client.{{ $m.Name }}(ctx, req)
}
{{- end }}

{{- with (eq .StreamType "Bidi") }}
func (c *GRPCClient) {{ $m.Name }}(ctx context.Context) ({{ $streamname }}, error) {
	return c.client.{{ $m.Name }}(ctx)
}
{{- end }}

{{- end }}
`))
