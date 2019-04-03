package main

var codeTmpl = `
{{- $c := .Client }}

{{ $typeConst := mkexpname $c.Prefix "Type" }}
{{ $pluginIntf := mkexpname $c.Prefix "Plugin" }}
{{ $pluginServerFunc := mkexpname $c.Prefix "PluginServer" }}
{{ $pluginServerImpl := mkname $c.Prefix "PluginServer" }}
{{ $pluginClientVar := mkexpname $c.Prefix "PluginClient" }}
{{ $pluginClientImpl := mkname $c.Prefix "PluginClient" }}
{{ $adaptPluginClientFunc := mkexpname "AdaptPluginClient" $c.Prefix }}
{{ $pluginClientAdapterImpl := mkname $c.Prefix "PluginClientAdapter" }}
{{ $serviceServerFunc := mkexpname $c.Prefix "ServiceServer" }}
{{ $serviceServerImpl := mkname $c.Prefix "ServiceServer" }}
{{ $serviceClientVar := mkexpname $c.Prefix "ServiceClient" }}
{{ $serviceClientImpl := mkname $c.Prefix "ServiceClient" }}
{{ $hostServerFunc := mkexpname $c.Prefix "HostServiceServer" }}
{{ $hostServerImpl := mkname $c.Prefix "HostServiceServer" }}
{{ $hostClientFunc := mkexpname $c.Prefix "HostServiceClient" }}
{{ $hostClientImpl := mkname $c.Prefix "HostServiceClient" }}
{{ $adaptServiceClientFunc := mkexpname "AdaptServiceClient" $c.Prefix }}
{{ $serviceClientAdapterImpl := mkname $c.Prefix "ServiceClientAdapter" }}

// Provides interfaces and adapters for the {{ $c.Name }} service
//
// Generated code. Do not modify by hand.
package {{ .Package }}

import (
{{- range .Imports }}
	{{ .As }}{{ printf "%q" .Path }}
{{- end }}
)

const (
	{{ $typeConst }} = "{{ $c.Name }}"
)

// {{ $c.Name }} is the client interface for the service type {{ $c.Name }} interface.
type {{ $c.Name }} interface {
	{{- range $c.Methods }}
	{{- if not .PluginOnly }}
	{{ .Name }}({{ range $i,$v := .Params }}{{ if $i }}, {{ end }}{{ $v.Type }}{{ end }}) ({{ range $i,$v := .Results }}{{ if $i }}, {{ end }}{{ $v.Type }}{{ end }})
	{{- end }}
	{{- end }}
}

{{- if eq .Mode "plugin" }}

// {{ $pluginIntf }} is the client interface for the service with the plugin related methods used by the catalog to initialize the plugin.
type {{ $pluginIntf }} interface {
	{{- range $c.Methods }}
	{{ .Name }}({{ range $i,$v := .Params }}{{ if $i }}, {{ end }}{{ $v.Type }}{{ end }}) ({{ range $i,$v := .Results }}{{ if $i }}, {{ end }}{{ $v.Type }}{{ end }})
	{{- end }}
}

// {{ $pluginServerFunc }} returns a catalog PluginServer implementation for the {{ $c.Name }} plugin.
func {{ $pluginServerFunc }}(server {{ $c.ServerType }}) interfaces.PluginServer {
	return &{{ $pluginServerImpl }}{
		server: server,
	}
}

type {{ $pluginServerImpl }} struct {
	server {{ $c.ServerType }}
}

func (s  {{ $pluginServerImpl }}) PluginType() string {
	return {{ $typeConst }}
}

func (s  {{ $pluginServerImpl }}) PluginClient() interfaces.PluginClient {
	return {{ $pluginClientVar }}
}

func (s {{ $pluginServerImpl }}) RegisterPluginServer(server *grpc.Server) interface{} {
	{{ $c.PkgQual }}Register{{ $c.Name }}Server(server, s.server)
	return s.server
}

// {{ $pluginClientVar }} is a catalog PluginClient implementation for the {{ $c.Name }} plugin.
var {{ $pluginClientVar }} interfaces.PluginClient = {{ $pluginClientImpl }}{}

type {{ $pluginClientImpl }} struct {}

func ({{ $pluginClientImpl }}) PluginType() string {
	return {{ $typeConst }}
}

func ({{ $pluginClientImpl }}) NewPluginClient(conn *grpc.ClientConn) interface{} {
	return {{ $adaptPluginClientFunc }}({{ $c.PkgQual }}New{{ $c.Name }}Client(conn))
}

func {{ $adaptPluginClientFunc }}(client {{ $c.ClientType }}) {{ $c.Name }} {
	return {{ $pluginClientAdapterImpl }}{client: client}
}

type {{ $pluginClientAdapterImpl }} struct {
	client {{ $c.ClientType }}
}

{{- range $c.Methods }}

func (a {{ $pluginClientAdapterImpl }}) {{ .Name }}({{ range $i,$v := .Params }}{{ if $i }}, {{ end }}{{ $v.Name }} {{ $v.Type }}{{ end }}) ({{ range $i,$v := .Results }}{{ if $i }}, {{ end }}{{ $v.Type }}{{ end }}) {
	return a.client.{{ .Name }}({{ range $i,$v := .Params }}{{ if $i }}, {{ end }}{{ $v.Name }}{{ end }})
}
{{- end }}

{{- else if eq .Mode "service" }}

// {{ $serviceServerFunc }} returns a catalog ServiceServer implementation for the {{ $c.Name }} plugin.
func {{ $serviceServerFunc }}(server {{ $c.ServerType }}) interfaces.ServiceServer {
	return &{{ $serviceServerImpl }}{
		server: server,
	}
}

type {{ $serviceServerImpl }} struct {
	server {{ $c.ServerType }}
}

func (s  {{ $serviceServerImpl }}) ServiceType() string {
	return {{ $typeConst }}
}

func (s  {{ $serviceServerImpl }}) ServiceClient() interfaces.ServiceClient {
	return {{ $serviceClientVar }}
}

func (s {{ $serviceServerImpl }}) RegisterServiceServer(server *grpc.Server) interface{} {
	{{ $c.PkgQual }}Register{{ $c.Name }}Server(server, s.server)
	return s.server
}

// {{ $serviceClientVar }} is a catalog ServiceClient implementation for the {{ $c.Name }} plugin.
var {{ $serviceClientVar }} interfaces.ServiceClient = {{ $serviceClientImpl }}{}

type {{ $serviceClientImpl }} struct {}

func ({{ $serviceClientImpl }}) ServiceType() string {
	return {{ $typeConst }}
}

func ({{ $serviceClientImpl }}) NewServiceClient(conn *grpc.ClientConn) interface{} {
	return {{ $adaptServiceClientFunc }}({{ $c.PkgQual }}New{{ $c.Name }}Client(conn))
}

func {{ $adaptServiceClientFunc }}(client {{ $c.ClientType }}) {{ $c.Name }} {
	return {{ $serviceClientAdapterImpl }}{client: client}
}

type {{ $serviceClientAdapterImpl }} struct {
	client {{ $c.ClientType }}
}

{{- range $c.Methods }}

func (a {{ $serviceClientAdapterImpl }}) {{ .Name }}({{ range $i,$v := .Params }}{{ if $i }}, {{ end }}{{ $v.Name }} {{ $v.Type }}{{ end }}) ({{ range $i,$v := .Results }}{{ if $i }}, {{ end }}{{ $v.Type }}{{ end }}) {
	return a.client.{{ .Name }}({{ range $i,$v := .Params }}{{ if $i }}, {{ end }}{{ $v.Name }}{{ end }})
}
{{- end }}

{{- else }}

// {{ $hostServerFunc }} returns a catalog HostServiceServer implementation for the {{ $c.Name }} plugin.
func {{ $hostServerFunc }}(server {{ $c.ServerType }}) interfaces.HostServiceServer {
	return &{{ $hostServerImpl }}{
		server: server,
	}
}

type {{ $hostServerImpl }} struct {
	server {{ $c.ServerType }}
}

func (s  {{ $hostServerImpl }}) HostServiceType() string {
	return {{ $typeConst }}
}

func (s {{ $hostServerImpl }}) RegisterHostServiceServer(server *grpc.Server) {
	{{ $c.PkgQual }}Register{{ $c.Name }}Server(server, s.server)
}

// {{ $hostServerFunc }} returns a catalog HostServiceServer implementation for the {{ $c.Name }} plugin.
func {{ $hostClientFunc }}(client *{{ $c.ClientType }}) interfaces.HostServiceClient {
	return &{{ $hostClientImpl }}{
		client: client,
	}
}

type {{ $hostClientImpl }} struct {
	client *{{ $c.ClientType }}
}

func (c *{{ $hostClientImpl }}) HostServiceType() string {
	return {{ $typeConst }}
}

func (c *{{ $hostClientImpl }}) InitHostServiceClient(conn *grpc.ClientConn) {
	*c.client = {{ $c.PkgQual }}New{{ $c.Name }}Client(conn)
}

{{- end }}
`
