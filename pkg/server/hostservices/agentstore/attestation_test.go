package agentstore

import (
	"context"
	"errors"
	"testing"

	"github.com/spiffe/spire/proto/spire/server/hostservices"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestEnsureNotAttested(t *testing.T) {
	assert := assert.New(t)
	store := fakeAgentStore{}

	err := EnsureNotAttested(context.Background(), store, "spiffe://domain.test/spire/agent/test/attested")
	assert.EqualError(err, "agent has already attested")

	err = EnsureNotAttested(context.Background(), store, "spiffe://domain.test/spire/agent/test/notattested")
	assert.NoError(err)

	err = EnsureNotAttested(context.Background(), store, "spiffe://domain.test/spire/agent/test/bad")
	assert.EqualError(err, "unable to get agent info: ohno")
}

func TestIsAttested(t *testing.T) {
	assert := assert.New(t)
	store := fakeAgentStore{}

	attested, err := IsAttested(context.Background(), store, "spiffe://domain.test/spire/agent/test/attested")
	assert.NoError(err)
	assert.True(attested)

	attested, err = IsAttested(context.Background(), store, "spiffe://domain.test/spire/agent/test/notattested")
	assert.NoError(err)
	assert.False(attested)

	attested, err = IsAttested(context.Background(), store, "spiffe://domain.test/spire/agent/test/bad")
	assert.EqualError(err, "unable to get agent info: ohno")
	assert.False(attested)
}

type fakeAgentStore struct{}

func (fakeAgentStore) GetAgentInfo(ctx context.Context, in *hostservices.GetAgentInfoRequest) (*hostservices.GetAgentInfoResponse, error) {
	switch in.AgentId {
	case "spiffe://domain.test/spire/agent/test/attested":
		return &hostservices.GetAgentInfoResponse{
			Info: &hostservices.AgentInfo{
				AgentId: in.AgentId,
			},
		}, nil
	case "spiffe://domain.test/spire/agent/test/bad":
		return nil, errors.New("ohno")
	default:
		return nil, status.Error(codes.NotFound, "agent not found")
	}
}
