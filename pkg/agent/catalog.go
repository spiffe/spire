package agent

import (
	"reflect"

	"github.com/spiffe/helpers"
	"github.com/spiffe/sri/agent/keymanager"
	"github.com/spiffe/sri/agent/nodeattestor"
	"github.com/spiffe/sri/agent/workloadattestor"
)

const (
	DefaultPluginConfigDir = "../../plugin/agent/.conf"

	PluginTypeMap = map[string]plugin.Plugin{
		"KeyManager":       &keymanager.KeyManagerPlugin{},
		"NodeAttestor":     &nodeattestor.NodeAttestorPlugin{},
		"WorkloadAttestor": &workloadattestor.WorkloadAttestorPlugin{},
	}

	MaxPlugins = map[string]int{
		"KeyManager":       1,
		"NodeAttestor":     1,
		"WorkloadAttestor": 1,
	}
)

type Catalog struct {
	ConfigDirectory string

	pluginCatalog *helpers.PluginCatalog
}

func (c *Catalog) KeyManager() (*keymanager.keyManagerClient, error) {
	// Should only be one key manager plugin present
	p, err := c.plugins("KeyManager")
	if err != nil {
		return nil, err
	}

	return keymanager.NewKeyManagerClient(p[0]), nil
}

func (c *Catalog) NodeAttestor() (*nodeattestor.NodeAttestorClient, error) {
	// Should only be one node attestor plugin present
	p, err := c.plugins("NodeAttestor")
	if err != nil {
		return nil, err
	}

	return nodeattestor.NewNodeAttestorClient(p[0])
}

func (c *Catalog) plugins(typeName string) ([]interface{}, error) {
	var p interface{}
	for _, p := range c.pluginCatalog.Plugins {
		if reflect.TypeOf(p) == PluginTypeMap[typeName] {
			manager = p
			break
		}
	}

	if p == nil {
		return nil, fmt.Errorf("Key manager plugin not found")
	}

	return p, nil
}
