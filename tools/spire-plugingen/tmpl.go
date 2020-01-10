package main

var codeTmpl = `
{{- $c := .Client }}

{{ $typeConst := mkexpname $c.Prefix "Type" }}
{{ $pluginIntf := mkexpname $c.Prefix "Plugin" }}
{{ $pluginServerFunc := mkexpname $c.Prefix "PluginServer" }}
{{ $pluginServerImpl := mkname $c.Prefix "PluginServer" }}
{{ $pluginClientVar := mkexpname $c.Prefix "PluginClient" }}
{{ $pluginClientImpl := mkname $c.Prefix "PluginClient" }}
{{ $adaptPluginClientFunc := mkexpname "Adapt" $c.Prefix "PluginClient" }}
{{ $pluginClientAdapterImpl := mkname $c.Prefix "PluginClientAdapter" }}
{{ $serviceServerFunc := mkexpname $c.Prefix "ServiceServer" }}
{{ $serviceServerImpl := mkname $c.Prefix "ServiceServer" }}
{{ $serviceClientVar := mkexpname $c.Prefix "ServiceClient" }}
{{ $serviceClientImpl := mkname $c.Prefix "ServiceClient" }}
{{ $adaptServiceClientFunc := mkexpname "Adapt" $c.Prefix "ServiceClient" }}
{{ $serviceClientAdapterImpl := mkname $c.Prefix "ServiceClientAdapter" }}
{{ $hostServiceServerFunc := mkexpname $c.Prefix "HostServiceServer" }}
{{ $hostServiceServerImpl := mkname $c.Prefix "HostServiceServer" }}
{{ $hostServiceClientFunc := mkexpname $c.Prefix "HostServiceClient" }}
{{ $hostServiceClientImpl := mkname $c.Prefix "HostServiceClient" }}
{{ $adaptHostServiceClientFunc := mkexpname "Adapt" $c.Prefix "HostServiceClient" }}
{{ $hostServiceClientAdapterImpl := mkname $c.Prefix "HostServiceClientAdapter" }}

// Provides interfaces and adapters for the {{ $c.Name }} service
//
// Generated code. Do not modify by hand.
package {{ .Package }}

import (
{{- range .Imports }}
	{{ .As }}{{ printf "%q" .Path }}
{{- end }}
)

{{- range .Aliases }}
type {{ .Name }} = {{ .Type }} //nolint: golint
{{- end }}

const (
	{{ $typeConst }} = "{{ $c.Name }}"
{{- range .Consts }}
	{{ .Name }} = {{ .Value }} //nolint: golint
{{- end }}
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
func {{ $pluginServerFunc }}(server {{ $c.ServerType }}) catalog.PluginServer {
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

func (s  {{ $pluginServerImpl }}) PluginClient() catalog.PluginClient {
	return {{ $pluginClientVar }}
}

func (s {{ $pluginServerImpl }}) RegisterPluginServer(server *grpc.Server) interface{} {
	{{ $c.PkgQual }}Register{{ $c.Name }}Server(server, s.server)
	return s.server
}

// {{ $pluginClientVar }} is a catalog PluginClient implementation for the {{ $c.Name }} plugin.
var {{ $pluginClientVar }} catalog.PluginClient = {{ $pluginClientImpl }}{}

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
func {{ $serviceServerFunc }}(server {{ $c.ServerType }}) catalog.ServiceServer {
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

func (s  {{ $serviceServerImpl }}) ServiceClient() catalog.ServiceClient {
	return {{ $serviceClientVar }}
}

func (s {{ $serviceServerImpl }}) RegisterServiceServer(server *grpc.Server) interface{} {
	{{ $c.PkgQual }}Register{{ $c.Name }}Server(server, s.server)
	return s.server
}

// {{ $serviceClientVar }} is a catalog ServiceClient implementation for the {{ $c.Name }} plugin.
var {{ $serviceClientVar }} catalog.ServiceClient = {{ $serviceClientImpl }}{}

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

// {{ $hostServiceServerFunc }} returns a catalog HostServiceServer implementation for the {{ $c.Name }} plugin.
func {{ $hostServiceServerFunc }}(server {{ $c.ServerType }}) catalog.HostServiceServer {
	return &{{ $hostServiceServerImpl }}{
		server: server,
	}
}

type {{ $hostServiceServerImpl }} struct {
	server {{ $c.ServerType }}
}

func (s  {{ $hostServiceServerImpl }}) HostServiceType() string {
	return {{ $typeConst }}
}

func (s {{ $hostServiceServerImpl }}) RegisterHostServiceServer(server *grpc.Server) {
	{{ $c.PkgQual }}Register{{ $c.Name }}Server(server, s.server)
}

// {{ $hostServiceServerFunc }} returns a catalog HostServiceServer implementation for the {{ $c.Name }} plugin.
func {{ $hostServiceClientFunc }}(client *{{ $c.Name }}) catalog.HostServiceClient {
	return &{{ $hostServiceClientImpl }}{
		client: client,
	}
}

type {{ $hostServiceClientImpl }} struct {
	client *{{ $c.Name }}
}

func (c *{{ $hostServiceClientImpl }}) HostServiceType() string {
	return {{ $typeConst }}
}

func (c *{{ $hostServiceClientImpl }}) InitHostServiceClient(conn *grpc.ClientConn) {
	*c.client = {{ $adaptHostServiceClientFunc }}({{ $c.PkgQual }}New{{ $c.Name }}Client(conn))
}

func {{ $adaptHostServiceClientFunc }}(client {{ $c.ClientType }}) {{ $c.Name }} {
	return {{ $hostServiceClientAdapterImpl }}{client: client}
}

type {{ $hostServiceClientAdapterImpl }} struct {
	client {{ $c.ClientType }}
}

{{- range $c.Methods }}

func (a {{ $hostServiceClientAdapterImpl }}) {{ .Name }}({{ range $i,$v := .Params }}{{ if $i }}, {{ end }}{{ $v.Name }} {{ $v.Type }}{{ end }}) ({{ range $i,$v := .Results }}{{ if $i }}, {{ end }}{{ $v.Type }}{{ end }}) {
	return a.client.{{ .Name }}({{ range $i,$v := .Params }}{{ if $i }}, {{ end }}{{ $v.Name }}{{ end }})
}
{{- end }}

{{- end }}
`
