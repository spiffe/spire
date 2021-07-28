package base

import (
	"context"
	"errors"

	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	"github.com/spiffe/spire/pkg/server/hostservice/agentstore"
)

type Base struct {
	store agentstorev1.AgentStoreServiceClient
}

var _ pluginsdk.NeedsHostServices = (*Base)(nil)

func (p *Base) BrokerHostServices(broker pluginsdk.ServiceBroker) error {
	if !broker.BrokerClient(&p.store) {
		return errors.New("required AgentStore host service not available")
	}
	return nil
}

func (p *Base) IsAttested(ctx context.Context, agentID string) (bool, error) {
	return agentstore.IsAttested(ctx, p.store, agentID)
}
