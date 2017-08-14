package main

import (
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/sri/control_plane/plugins/common/proto"
	"github.com/spiffe/sri/control_plane/plugins/control_plane_ca"
)

type MemoryPlugin struct{}

func (MemoryPlugin) Configure(config string) ([]string, error) {
	return []string{}, nil
}

func (MemoryPlugin) GetPluginInfo() (*common.GetPluginInfoResponse, error) {
	return nil, nil
}

func (MemoryPlugin) SignCsr(csr []byte) (signedCertificate []byte, err error) {
	return []byte{}, nil
}

func (MemoryPlugin) GenerateCsr() (csr []byte, err error) {
	return []byte{}, nil
}

func (MemoryPlugin) FetchCertificate() (storedIntermediateCert []byte, err error) {
	return []byte{}, nil
}

func (MemoryPlugin) LoadCertificate(signedIntermediateCert []byte) (err error) {
	return nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: controlplaneca.Handshake,
		Plugins: map[string]plugin.Plugin{
			"cpca_memory": controlplaneca.ControlPlaneCaPlugin{ControlPlaneCaImpl: &MemoryPlugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
