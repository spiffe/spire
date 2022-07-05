package agentstore

import (
	"context"
	"errors"

	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func EnsureNotAttested(ctx context.Context, store agentstorev1.AgentStoreClient, agentID string) error {
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

func IsAttested(ctx context.Context, store agentstorev1.AgentStoreClient, agentID string) (bool, error) {
	_, err := store.GetAgentInfo(ctx, &agentstorev1.GetAgentInfoRequest{
		AgentId: agentID,
	})
	st := status.Convert(err)
	switch st.Code() {
	case codes.OK:
		return true, nil
	case codes.NotFound:
		return false, nil
	default:
		return false, status.Errorf(st.Code(), "unable to get agent info: %s", st.Message())
	}
}
