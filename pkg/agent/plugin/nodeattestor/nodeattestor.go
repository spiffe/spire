package nodeattestor

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
)

// NodeAttestor attests the agent with the server
type NodeAttestor interface {
	catalog.PluginInfo

	// Attest attests the agent with the server using the provided server
	// stream. Errors produced by the ServerStream are returned from this
	// function unchanged.
	Attest(ctx context.Context, serverStream ServerStream) error
}

// ServerStream is used by the NodeAttestor to send the attestation data and
// challenge responses to the server.
type ServerStream interface {
	SendAttestationData(ctx context.Context, attestationData AttestationData) ([]byte, error)
	SendChallengeResponse(ctx context.Context, response []byte) ([]byte, error)
}

// AttestationData represents the attestation type and payload that is sent
// to the server.
type AttestationData struct {
	Type    string
	Payload []byte
}
