package sriplugin

import "github.com/hashicorp/go-plugin"

type PluginCatalog interface {
	loadConfig() error
	SetPluginTypeMap(map[string]plugin.Plugin)
	SetMaxPluginTypeMap(map[string]int)
	GetPluginByName(string) interface{}
	GetPluginsByType(string) []interface{}
	GetAllPlugins() map[string]*PluginClients
	initClients() error
	ConfigureClients() error
	Run() error
	Stop()
}
