package base

import (
	"context"
	"errors"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/hostservices/agentstore"
	"github.com/spiffe/spire/pkg/server/plugin/hostservices"
)

type Base struct {
	store hostservices.AgentStore
}

func (p *Base) BrokerHostServices(broker catalog.HostServiceBroker) error {
	has, err := broker.GetHostService(hostservices.AgentStoreHostServiceClient(&p.store))
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
