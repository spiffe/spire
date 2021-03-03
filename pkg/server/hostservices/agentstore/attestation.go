package agentstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/plugin/hostservices"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func EnsureNotAttested(ctx context.Context, store hostservices.AgentStore, agentID spiffeid.ID) error {
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

func IsAttested(ctx context.Context, store hostservices.AgentStore, agentID spiffeid.ID) (bool, error) {
	_, err := store.GetAgentInfo(ctx, &hostservices.GetAgentInfoRequest{
		AgentId: agentID.String(),
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
