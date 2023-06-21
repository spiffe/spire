package jointoken

import (
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	PluginName = "join_token"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(PluginName, nodeattestorv1.NodeAttestorPluginServer(p))
}

type Plugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) AidAttestation(_ nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	// The agent handles the case where the join token is set using special
	// cased code. The special code is only activated when the join token has
	// been provided via CLI flag or HCL configuration, whether or not the
	// join_token node attestor has been configured. If the join token is not
	// set, but the join_token node attestor is configured, then the special
	// case code will not be activated and this plugin will end up being
	// invoked. The message we return here should educate operators that they
	// failed to provide a join token.
	return status.Error(codes.InvalidArgument, "join token was not provided")
}
