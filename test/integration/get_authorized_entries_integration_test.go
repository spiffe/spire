package integration

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/pb"
	"github.com/spiffe/spire/test/integration/setup"
	"github.com/stretchr/testify/require"
)

func TestGetAuthorizedEntries(t *testing.T) {
	// Setup SPIRE server and agent
	srv := setup.NewSpireServer(t)
	defer srv.Stop()

	agent := setup.NewSpireAgent(t, srv)
	defer agent.Stop()

	// Create a Join Token
	joinToken := "test-join-token"
	_, err := srv.CreateJoinToken(&pb.JoinToken{
		Token: joinToken,
		Ttl:   600, // Token validity in seconds
	})
	require.NoError(t, err)

	// Attest the agent using the join token
	err = agent.AttestWithJoinToken(joinToken)
	require.NoError(t, err)

	// Create a Node-Alias-based registration entry
	parentID := "spiffe://example/spire/agent/tpm/xxxxx"
	spiffeID := "spiffe://example/nodename/foo"
	_, err = srv.CreateRegistrationEntry(&pb.RegistrationEntry{
		ParentId: parentID,
		SpiffeId: spiffeID,
		Selectors: []*pb.Selector{
			{Type: "tpm", Value: "pub_hash:xxxxx"},
		},
	})
	require.NoError(t, err)

	// Enable event-driven cache validation on SPIRE server
	srv.EnableEventDrivenCacheValidation()

	// Wait for the cache to update
	time.Sleep(2 * time.Second)

	// Test the GetAuthorizedEntries RPC
	client := srv.NewClient()
	resp, err := client.GetAuthorizedEntries(context.Background(), &pb.GetAuthorizedEntriesRequest{})
	require.NoError(t, err)

	// Validate the response
	require.NotNil(t, resp)
	require.Len(t, resp.Entries, 1)
	require.Equal(t, spiffeID, resp.Entries[0].SpiffeId)
}
