package secretfile

import (
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/node-agent/plugins/workload_attestor"
)

type SecretFilePlugin struct{}

func (SecretFilePlugin) Attest(pid int32) (selectors []string, err error) {
	return []string{}, nil
}

func (SecretFilePlugin) Configure(configuration string) error {
	return nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: workloadattestor.Handshake,
		Plugins: map[string]plugin.Plugin{
			"workloadattestor": workloadattestor.WorkloadAttestorPlugin{WorkloadAttestorImpl: &SecretFilePlugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
