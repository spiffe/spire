package psat

import (
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/k8s/common"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
)

const (
	pluginName       = "k8s_psat"
	defaultTokenPath = "/var/run/secrets/tokens/psat"
	satErrorName     = "k8s-psat"
)

type PSATAttestorPlugin struct {
	*common.CommonAttestorPlugin
}

var _ nodeattestor.Plugin = (*PSATAttestorPlugin)(nil)

func NewPSATAttestorPlugin() *PSATAttestorPlugin {
	p := &PSATAttestorPlugin{
		CommonAttestorPlugin: common.NewCommonAttestorPlugin(pluginName, defaultTokenPath, satErrorName),
	}
	return p
}
