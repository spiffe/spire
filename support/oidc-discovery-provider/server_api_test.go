package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestServerAPISource(t *testing.T) {
	const pollInterval = time.Second

	api := &fakeServerAPIServer{}

	addr := spiretest.StartGRPCServer(t, func(s *grpc.Server) {
		bundlev1.RegisterBundleServer(s, api)
	})

	log, _ := test.NewNullLogger()
	clock := clock.NewMock(t)

	target, err := util.GetTargetName(addr)
	require.NoError(t, err)
	source, err := NewServerAPISource(ServerAPISourceConfig{
		Log:          log,
		GRPCTarget:   target,
		PollInterval: pollInterval,
		Clock:        clock,
	})
	require.NoError(t, err)
	defer source.Close()

	// Wait for the poll to happen and assert there is no key set available
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	_, _, ok := source.FetchKeySet()
	require.False(t, ok, "No bundle was available but we have a keyset somehow")
	require.Equal(t, 1, api.GetBundleCount())

	// Add a bundle, step forward past the poll interval, wait for polling,
	// and assert we have a keyset.
	api.SetBundle(&types.Bundle{
		JwtAuthorities: []*types.JWTKey{
			{
				KeyId:     "KID",
				PublicKey: ec256PubkeyPKIX,
			},
		},
	})
	clock.Add(pollInterval)
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	require.Equal(t, 2, api.GetBundleCount())
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
	require.Equal(t, 3, api.GetBundleCount())
	require.Equal(t, keySet1, keySet2)
	require.Equal(t, modTime1, modTime2)

	// Change the bundle, step forward past the poll interval, wait for polling,
	// and assert that the changes have been picked up.
	api.SetBundle(&types.Bundle{
		JwtAuthorities: []*types.JWTKey{
			{
				KeyId:     "KID2",
				PublicKey: ec256PubkeyPKIX,
			},
		},
	})
	clock.Add(pollInterval)
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	require.Equal(t, 4, api.GetBundleCount())
	keySet3, modTime3, ok := source.FetchKeySet()
	require.True(t, ok)
	require.Equal(t, clock.Now(), modTime3)
	require.NotNil(t, keySet3)
	require.Len(t, keySet3.Keys, 1)
	require.Equal(t, "KID2", keySet3.Keys[0].KeyID)
	require.Equal(t, ec256Pubkey, keySet3.Keys[0].Key)
}

type fakeServerAPIServer struct {
	bundlev1.BundleServer

	mu             sync.Mutex
	bundle         *types.Bundle
	getBundleCount int
}

func (s *fakeServerAPIServer) SetBundle(bundle *types.Bundle) {
	s.mu.Lock()
	s.bundle = bundle
	s.mu.Unlock()
}

func (s *fakeServerAPIServer) GetBundleCount() int {
	s.mu.Lock()
	count := s.getBundleCount
	s.mu.Unlock()
	return count
}

func (s *fakeServerAPIServer) GetBundle(ctx context.Context, req *bundlev1.GetBundleRequest) (*types.Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getBundleCount++
	if s.bundle == nil {
		return nil, status.Error(codes.NotFound, "no bundle")
	}
	return s.bundle, nil
}
