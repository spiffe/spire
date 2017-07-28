package memory

import (
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/control-plane/plugins/control_plane_ca"
)

type MemoryPlugin struct{}

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
			"controlplaneca": controlplaneca.ControlPlaneCaPlugin{ControlPlaneCaImpl: &MemoryPlugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
