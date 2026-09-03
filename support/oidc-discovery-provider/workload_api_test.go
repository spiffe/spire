package main

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestWorkloadAPISource(t *testing.T) {
	const pollInterval = time.Second

	api := &fakeWorkloadAPIServer{}

	addr := spiretest.StartWorkloadAPI(t, api)
	log, _ := test.NewNullLogger()
	clock := clock.NewMock(t)

	source, err := NewWorkloadAPISource(WorkloadAPISourceConfig{
		Log:          log,
		Addr:         addr,
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

	// Wait another poll interval, ensure the bundle was re-fetched and that the
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

func TestWorkloadAPISourceBundle(t *testing.T) {
	const pollInterval = time.Second

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := testca.New(t, td)

	api := &fakeWorkloadAPIServer{}

	addr := spiretest.StartWorkloadAPI(t, api)
	log, _ := test.NewNullLogger()
	clock := clock.NewMock(t)

	source, err := NewWorkloadAPISource(WorkloadAPISourceConfig{
		Log:          log,
		Addr:         addr,
		TrustDomain:  td.Name(),
		PollInterval: pollInterval,
		Clock:        clock,
	})
	require.NoError(t, err)
	defer source.Close()

	// Wait for the poll to happen and assert there is no bundle available
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	_, _, ok := source.FetchBundle()
	require.False(t, ok, "No bundle was available but we have one somehow")

	// Serve only JWT authorities. Without the X.509 authorities the source
	// cannot assemble a trust bundle, but the key set still works.
	api.SetJWTBundles(map[string][]byte{
		"spiffe://domain.test": makeJWKS(t, &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{KeyID: "KID", Key: ec256Pubkey}},
		}),
	})
	clock.Add(pollInterval)
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	_, _, ok = source.FetchKeySet()
	require.True(t, ok)
	_, _, ok = source.FetchBundle()
	require.False(t, ok, "X.509 authorities are unavailable but we have a bundle somehow")

	// Now serve the X.509 authorities as well and assert the assembled bundle
	// contains both kinds of authority.
	api.SetX509Bundles(map[string][]byte{
		"spiffe://domain.test": marshalX509Authorities(ca.X509Authorities()),
	})
	clock.Add(pollInterval)
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	bundle1, modTime1, ok := source.FetchBundle()
	require.True(t, ok)
	require.Equal(t, clock.Now(), modTime1)
	require.Equal(t, ca.X509Authorities(), bundle1.X509Authorities())
	require.Equal(t, map[string]crypto.PublicKey{"KID": ec256Pubkey}, bundle1.JWTAuthorities())

	// The Workload API conveys neither a refresh hint nor a sequence number.
	_, ok = bundle1.RefreshHint()
	require.False(t, ok)
	_, ok = bundle1.SequenceNumber()
	require.False(t, ok)

	// Poll again without changing anything and assert the bundle is unchanged.
	clock.Add(pollInterval)
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	bundle2, modTime2, ok := source.FetchBundle()
	require.True(t, ok)
	require.True(t, bundle1.Equal(bundle2))
	require.Equal(t, modTime1, modTime2)

	// Change the X.509 authorities and assert the change is picked up.
	otherCA := testca.New(t, td)
	api.SetX509Bundles(map[string][]byte{
		"spiffe://domain.test": marshalX509Authorities(otherCA.X509Authorities()),
	})
	clock.Add(pollInterval)
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	bundle3, modTime3, ok := source.FetchBundle()
	require.True(t, ok)
	require.Equal(t, clock.Now(), modTime3)
	require.NotEqual(t, modTime1, modTime3)
	require.Equal(t, otherCA.X509Authorities(), bundle3.X509Authorities())

	require.NotZero(t, api.GetFetchX509BundlesCount())
}

func marshalX509Authorities(authorities []*x509.Certificate) []byte {
	var der []byte
	for _, authority := range authorities {
		der = append(der, authority.Raw...)
	}
	return der
}

type fakeWorkloadAPIServer struct {
	workload.SpiffeWorkloadAPIServer

	mu                    sync.Mutex
	bundles               map[string][]byte
	x509Bundles           map[string][]byte
	fetchJWTBundlesCount  int
	fetchX509BundlesCount int
}

func (s *fakeWorkloadAPIServer) SetJWTBundles(bundles map[string][]byte) {
	s.mu.Lock()
	s.bundles = bundles
	s.mu.Unlock()
}

func (s *fakeWorkloadAPIServer) SetX509Bundles(bundles map[string][]byte) {
	s.mu.Lock()
	s.x509Bundles = bundles
	s.mu.Unlock()
}

func (s *fakeWorkloadAPIServer) GetFetchJWTBundlesCount() int {
	s.mu.Lock()
	count := s.fetchJWTBundlesCount
	s.mu.Unlock()
	return count
}

func (s *fakeWorkloadAPIServer) GetFetchX509BundlesCount() int {
	s.mu.Lock()
	count := s.fetchX509BundlesCount
	s.mu.Unlock()
	return count
}

func (s *fakeWorkloadAPIServer) FetchX509Bundles(_ *workload.X509BundlesRequest, stream workload.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fetchX509BundlesCount++

	if s.x509Bundles == nil {
		return status.Error(codes.NotFound, "no bundle")
	}

	// Send the X.509 bundles right away
	if err := stream.Send(&workload.X509BundlesResponse{
		Bundles: s.x509Bundles,
	}); err != nil {
		return err
	}

	// Wait for the stream to close down
	<-stream.Context().Done()
	return nil
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
