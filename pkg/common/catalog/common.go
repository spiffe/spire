package catalog

import (
	"fmt"
	"io/ioutil"
	"sort"

	"github.com/sirupsen/logrus"
	"github.com/zeebo/errs"
)

type Plugin struct {
	Name     string
	Plugin   PluginServer
	Services []ServiceServer
}

func MakePlugin(name string, plugin PluginServer, services ...ServiceServer) Plugin {
	return Plugin{
		Name:     name,
		Plugin:   plugin,
		Services: services,
	}
}

func newDiscardingLogger() logrus.FieldLogger {
	log := logrus.New()
	log.SetOutput(ioutil.Discard)
	return log
}

func makePluginsMap(knownPlugins []PluginClient) (map[string]PluginClient, error) {
	m := map[string]PluginClient{}
	for _, knownPlugin := range knownPlugins {
		if _, ok := m[knownPlugin.PluginType()]; ok {
			return nil, errs.New("duplicate plugin type %q", knownPlugin.PluginType())
		}
		m[knownPlugin.PluginType()] = knownPlugin
	}
	return m, nil
}

func makeServicesMap(knownServices []ServiceClient) (map[string]ServiceClient, error) {
	m := map[string]ServiceClient{}
	for _, knownService := range knownServices {
		if _, ok := m[knownService.ServiceType()]; ok {
			return nil, errs.New("duplicate service type %q", knownService.ServiceType())
		}
		m[knownService.ServiceType()] = knownService
	}
	return m, nil
}

func makeHostServiceTypes(hostServices []HostServiceServer) ([]string, error) {
	m := map[string]bool{}
	for _, hostService := range hostServices {
		if _, ok := m[hostService.HostServiceType()]; ok {
			return nil, errs.New("duplicate host service type %q", hostService.HostServiceType())
		}
		m[hostService.HostServiceType()] = true
	}
	var types []string
	for typ := range m {
		types = append(types, typ)
	}
	sort.Strings(types)
	return types, nil
}

type builtinKey struct {
	Name string
	Type string
}

type builtinsMap map[builtinKey]Plugin

func (m builtinsMap) Lookup(name, typ string) (Plugin, bool) {
	v, ok := m[builtinKey{Name: name, Type: typ}]
	return v, ok
}

func makeBuiltInsMap(builtins []Plugin) (builtinsMap, error) {
	m := builtinsMap{}
	for _, builtin := range builtins {
		k := builtinKey{Name: builtin.Name, Type: builtin.Plugin.PluginType()}
		if _, ok := m[k]; ok {
			return nil, fmt.Errorf("duplicate %s builtin %q", k.Type, k.Name)
		}
		m[k] = builtin
	}
	return m, nil
}
