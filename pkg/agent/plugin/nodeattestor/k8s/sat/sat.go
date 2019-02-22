package sat

import (
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/k8s/common"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
)

const (
	pluginName       = "k8s_sat"
	defaultTokenPath = "/run/secrets/kubernetes.io/serviceaccount/token"
	satErrorName     = "k8s-sat"
)

type SATAttestorPlugin struct {
	*common.CommonAttestorPlugin
}

var _ nodeattestor.Plugin = (*SATAttestorPlugin)(nil)

func NewSATAttestorPlugin() *SATAttestorPlugin {
	p := &SATAttestorPlugin{
		CommonAttestorPlugin: common.NewCommonAttestorPlugin(pluginName, defaultTokenPath, satErrorName),
	}
	return p
}
