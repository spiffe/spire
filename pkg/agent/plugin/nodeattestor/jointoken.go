package nodeattestor

import (
	"context"

	"github.com/spiffe/spire/pkg/common/plugin"
	"google.golang.org/grpc/codes"
)

func JoinToken(token string) NodeAttestor {
	return joinToken{
		Facade: plugin.FixedFacade("join_token", "NodeAttestor"),
		token:  token,
	}
}

type joinToken struct {
	plugin.Facade
	token string
}

func (plugin joinToken) Attest(ctx context.Context, serverStream ServerStream) error {
	challenge, err := serverStream.SendAttestationData(ctx, AttestationData{
		Type:    plugin.Name(),
		Payload: []byte(plugin.token),
	})
	switch {
	case err != nil:
		return err
	case challenge != nil:
		return plugin.Error(codes.Internal, "server issued unexpected challenge")
	default:
		return nil
	}
}
