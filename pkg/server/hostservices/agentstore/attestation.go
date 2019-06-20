package agentstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/spiffe/spire/proto/spire/server/hostservices"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func EnsureNotAttested(ctx context.Context, store hostservices.AgentStore, agentID string) error {
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

func IsAttested(ctx context.Context, store hostservices.AgentStore, agentID string) (bool, error) {
	_, err := store.GetAgentInfo(ctx, &hostservices.GetAgentInfoRequest{
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
