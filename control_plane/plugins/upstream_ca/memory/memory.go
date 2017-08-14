package main

import (
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/sri/control_plane/plugins/common/proto"
	"github.com/spiffe/sri/control_plane/plugins/upstream_ca"
	"github.com/spiffe/sri/control_plane/plugins/upstream_ca/proto"
)

type MemoryPlugin struct{}

func (MemoryPlugin) Configure(config string) ([]string, error) {
	return []string{}, nil
}

func (MemoryPlugin) GetPluginInfo() (*common.GetPluginInfoResponse, error) {
	return nil, nil
}

func (MemoryPlugin) SubmitCSR(csr []byte) (*proto.SubmitCSRResponse, error) {
	return &proto.SubmitCSRResponse{}, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: upstreamca.Handshake,
		Plugins: map[string]plugin.Plugin{
			"uca_memory": upstreamca.UpstreamCaPlugin{UpstreamCaImpl: &MemoryPlugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
