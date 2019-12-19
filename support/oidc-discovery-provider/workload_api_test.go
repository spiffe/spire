package main

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/proto/spiffe/workload"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/square/go-jose.v2"
)

func TestWorkloadAPISource(t *testing.T) {
	const pollInterval = time.Second

	api := &fakeWorkloadAPIServer{}

	// Create a temporary directory to host the socket
	socketPath, closeServer := spiretest.StartWorkloadAPIOnTempSocket(t, api)
	defer closeServer()

	log, _ := test.NewNullLogger()
	clock := clock.NewMock(t)

	source, err := NewWorkloadAPISource(WorkloadAPISourceConfig{
		Log:          log,
		SocketPath:   socketPath,
		TrustDomain:  "domain.test",
		PollInterval: pollInterval,
		Clock:        clock,
	})
	require.NoError(t, err)
	defer source.Close()

	// Wait for the poll to happen and assert there is no key set available
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	_, _, ok := source.FetchKeySet()
	require.False(t, ok, "No bundle was available but we have a keyset somehow")
	require.Equal(t, 1, api.GetFetchJWTBundlesCount())

	// Set a bundle without an entry for the trust domain, advance to the next
	// period, wait for the poll to happen and assert there is no key set
	// available
	api.SetJWTBundles(map[string][]byte{})
	clock.Add(pollInterval)
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	_, _, ok = source.FetchKeySet()
	require.False(t, ok, "No bundle was available but we have a keyset somehow")
	require.Equal(t, 2, api.GetFetchJWTBundlesCount())

	// Add a bundle, step forward past the poll interval, wait for polling,
	// and assert we have a keyset.
	api.SetJWTBundles(map[string][]byte{
		"spiffe://domain.test": makeJWKS(t, &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					KeyID: "KID",
					Key:   ec256Pubkey,
				},
			},
		}),
	})
	clock.Add(pollInterval)
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	require.Equal(t, 3, api.GetFetchJWTBundlesCount())
	keySet1, modTime1, ok := source.FetchKeySet()
	require.True(t, ok)
	require.Equal(t, clock.Now(), modTime1)
	require.NotNil(t, keySet1)
	require.Len(t, keySet1.Keys, 1)
	require.Equal(t, "KID", keySet1.Keys[0].KeyID)
	require.Equal(t, ec256Pubkey, keySet1.Keys[0].Key)

	// Wait another poll interval, ensure the bundle was refetched and that the
	// source reports no changes since nothing changed.
	clock.Add(pollInterval)
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	keySet2, modTime2, ok := source.FetchKeySet()
	require.True(t, ok)
	require.Equal(t, 4, api.GetFetchJWTBundlesCount())
	require.Equal(t, keySet1, keySet2)
	require.Equal(t, modTime1, modTime2)

	// Change the bundle, step forward past the poll interval, wait for polling,
	// and assert that the changes have been picked up.
	api.SetJWTBundles(map[string][]byte{
		"spiffe://domain.test": makeJWKS(t, &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					KeyID: "KID2",
					Key:   ec256Pubkey,
				},
			},
		}),
	})
	clock.Add(pollInterval)
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	require.Equal(t, 5, api.GetFetchJWTBundlesCount())
	keySet3, modTime3, ok := source.FetchKeySet()
	require.True(t, ok)
	require.Equal(t, clock.Now(), modTime3)
	require.NotNil(t, keySet3)
	require.Len(t, keySet3.Keys, 1)
	require.Equal(t, "KID2", keySet3.Keys[0].KeyID)
	require.Equal(t, ec256Pubkey, keySet3.Keys[0].Key)
}

type fakeWorkloadAPIServer struct {
	workload.SpiffeWorkloadAPIServer

	mu                   sync.Mutex
	bundles              map[string][]byte
	fetchJWTBundlesCount int
}

func (s *fakeWorkloadAPIServer) SetJWTBundles(bundles map[string][]byte) {
	s.mu.Lock()
	s.bundles = bundles
	s.mu.Unlock()
}

func (s *fakeWorkloadAPIServer) GetFetchJWTBundlesCount() int {
	s.mu.Lock()
	count := s.fetchJWTBundlesCount
	s.mu.Unlock()
	return count
}

func (s *fakeWorkloadAPIServer) FetchJWTBundles(_ *workload.JWTBundlesRequest, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fetchJWTBundlesCount++

	if s.bundles == nil {
		return status.Error(codes.NotFound, "no bundle")
	}

	// Send the JWT bundles right away
	if err := stream.Send(&workload.JWTBundlesResponse{
		Bundles: s.bundles,
	}); err != nil {
		return err
	}

	// Wait for the stream to close down
	<-stream.Context().Done()
	return nil
}

func makeJWKS(t *testing.T, jwks *jose.JSONWebKeySet) []byte {
	out, err := json.Marshal(jwks)
	require.NoError(t, err)
	return out
}
