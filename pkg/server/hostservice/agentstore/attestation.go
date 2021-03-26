package agentstore

import (
	"context"
	"errors"
	"fmt"

	agentstorev0 "github.com/spiffe/spire/proto/spire/hostservice/server/agentstore/v0"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func EnsureNotAttested(ctx context.Context, store agentstorev0.AgentStoreClient, agentID string) error {
	attested, err := IsAttested(ctx, store, agentID)
	switch {
	case err != nil:
		return err
	case attested:
		return errors.New("agent has already attested")
	default:
		return nil
	}
}

func IsAttested(ctx context.Context, store agentstorev0.AgentStoreClient, agentID string) (bool, error) {
	_, err := store.GetAgentInfo(ctx, &agentstorev0.GetAgentInfoRequest{
		AgentId: agentID,
	})
	switch status.Code(err) {
	case codes.OK:
		return true, nil
	case codes.NotFound:
		return false, nil
	default:
		return false, fmt.Errorf("unable to get agent info: %v", err)
	}
}
