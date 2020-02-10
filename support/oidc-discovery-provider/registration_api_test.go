package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRegistrationAPISource(t *testing.T) {
	const pollInterval = time.Second

	api := &fakeRegistrationAPIServer{}

	// Create a temporary directory to host the socket
	socketPath, closeServer := spiretest.StartRegistrationAPIOnTempSocket(t, api)
	defer closeServer()

	log, _ := test.NewNullLogger()
	clock := clock.NewMock(t)

	source, err := NewRegistrationAPISource(RegistrationAPISourceConfig{
		Log:          log,
		SocketPath:   socketPath,
		PollInterval: pollInterval,
		Clock:        clock,
	})
	require.NoError(t, err)
	defer source.Close()

	// Wait for the poll to happen and assert there is no key set available
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	_, _, ok := source.FetchKeySet()
	require.False(t, ok, "No bundle was available but we have a keyset somehow")
	require.Equal(t, 1, api.GetFetchBundleCount())

	// Add a bundle, step forward past the poll interval, wait for polling,
	// and assert we have a keyset.
	api.SetBundle(&common.Bundle{
		JwtSigningKeys: []*common.PublicKey{
			{
				Kid:       "KID",
				PkixBytes: ec256PubkeyPKIX,
			},
		},
	})
	clock.Add(pollInterval)
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	require.Equal(t, 2, api.GetFetchBundleCount())
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
	require.Equal(t, 3, api.GetFetchBundleCount())
	require.Equal(t, keySet1, keySet2)
	require.Equal(t, modTime1, modTime2)

	// Change the bundle, step forward past the poll interval, wait for polling,
	// and assert that the changes have been picked up.
	api.SetBundle(&common.Bundle{
		JwtSigningKeys: []*common.PublicKey{
			{
				Kid:       "KID2",
				PkixBytes: ec256PubkeyPKIX,
			},
		},
	})
	clock.Add(pollInterval)
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	require.Equal(t, 4, api.GetFetchBundleCount())
	keySet3, modTime3, ok := source.FetchKeySet()
	require.True(t, ok)
	require.Equal(t, clock.Now(), modTime3)
	require.NotNil(t, keySet3)
	require.Len(t, keySet3.Keys, 1)
	require.Equal(t, "KID2", keySet3.Keys[0].KeyID)
	require.Equal(t, ec256Pubkey, keySet3.Keys[0].Key)
}

type fakeRegistrationAPIServer struct {
	registration.RegistrationServer

	mu               sync.Mutex
	bundle           *common.Bundle
	fetchBundleCount int
}

func (s *fakeRegistrationAPIServer) SetBundle(bundle *common.Bundle) {
	s.mu.Lock()
	s.bundle = bundle
	s.mu.Unlock()
}

func (s *fakeRegistrationAPIServer) GetFetchBundleCount() int {
	s.mu.Lock()
	count := s.fetchBundleCount
	s.mu.Unlock()
	return count
}

func (s *fakeRegistrationAPIServer) FetchBundle(context.Context, *common.Empty) (*registration.Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fetchBundleCount++
	if s.bundle == nil {
		return nil, status.Error(codes.NotFound, "no bundle")
	}
	return &registration.Bundle{
		Bundle: s.bundle,
	}, nil
}
