package base

import (
	"context"
	"errors"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/hostservice/agentstore"
	agentstorev0 "github.com/spiffe/spire/proto/spire/hostservice/server/agentstore/v0"
	nodeattestorv0 "github.com/spiffe/spire/proto/spire/plugin/server/nodeattestor/v0"
)

type Base struct {
	nodeattestorv0.UnsafeNodeAttestorServer

	store agentstorev0.AgentStore
}

func (p *Base) BrokerHostServices(broker catalog.HostServiceBroker) error {
	has, err := broker.GetHostService(agentstorev0.HostServiceClient(&p.store))
	if err != nil {
		return err
	}
	if !has {
		return errors.New("required AgentStore host service not available")
	}
	return nil
}

func (p *Base) IsAttested(ctx context.Context, agentID string) (bool, error) {
	return agentstore.IsAttested(ctx, p.store, agentID)
}
