package base

import (
	"context"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/hostservice/agentstore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Base struct {
	store agentstorev1.AgentStoreServiceClient
}

var _ pluginsdk.NeedsHostServices = (*Base)(nil)

func (p *Base) BrokerHostServices(broker pluginsdk.ServiceBroker) error {
	if !broker.BrokerClient(&p.store) {
		return status.Error(codes.Internal, "required AgentStore host service not available")
	}
	return nil
}

func (p *Base) AssessTOFU(ctx context.Context, agentID string, log hclog.Logger) error {
	attested, err := agentstore.IsAttested(ctx, p.store, agentID)
	switch {
	case err != nil:
		return err
	case attested:
		log.Error("Attestation data has already been used to attest an agent", telemetry.SPIFFEID, agentID)
		return status.Error(codes.PermissionDenied, "attestation data has already been used to attest an agent")
	default:
		return nil
	}
}
