package api

import (
	"context"
	"errors"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	workloadattestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	k8sType = "type.googleapis.com/spiffe.broker.KubernetesObjectReference"
	pidType = "type.googleapis.com/spiffe.broker.PIDReference"
)

func udsContext() context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.UnixAddr{Name: "/tmp/broker.sock", Net: "unix"},
	})
}

func tcpContext() context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345},
	})
}

func ref(typeURL string) *anypb.Any {
	if typeURL == "" {
		return nil
	}
	return &anypb.Any{TypeUrl: typeURL}
}

func TestIsTCPCaller(t *testing.T) {
	assert.True(t, isTCPCaller(tcpContext()))
	assert.False(t, isTCPCaller(udsContext()))
	assert.False(t, isTCPCaller(context.Background()))
}

func TestAuthorizeReferenceType(t *testing.T) {
	caller := spiffeid.RequireFromString("spiffe://example.org/broker")
	other := spiffeid.RequireFromString("spiffe://example.org/other")

	for _, tt := range []struct {
		name       string
		byCaller   map[spiffeid.ID]ReferenceTypePolicy
		ctx        context.Context
		caller     spiffeid.ID
		ref        *anypb.Any
		expectCode codes.Code
	}{
		{
			name:       "nil reference is rejected before any gate",
			ctx:        udsContext(),
			caller:     caller,
			ref:        ref(""),
			expectCode: codes.InvalidArgument,
		},
		{
			name:       "empty type url is rejected",
			ctx:        udsContext(),
			caller:     caller,
			ref:        &anypb.Any{},
			expectCode: codes.InvalidArgument,
		},
		{
			name: "caller present and type allowed over UDS",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				Types: map[string]ReferenceTypeAccess{k8sType: {}},
			}},
			ctx:        udsContext(),
			caller:     caller,
			ref:        ref(k8sType),
			expectCode: codes.OK,
		},
		{
			name: "caller present and type not allowed",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				Types: map[string]ReferenceTypeAccess{k8sType: {}},
			}},
			ctx:        udsContext(),
			caller:     caller,
			ref:        ref(pidType),
			expectCode: codes.PermissionDenied,
		},
		{
			name: "caller absent from map behaves as wildcard over UDS",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{other: {
				Types: map[string]ReferenceTypeAccess{k8sType: {}},
			}},
			ctx:        udsContext(),
			caller:     caller,
			ref:        ref(pidType),
			expectCode: codes.OK,
		},
		{
			name: "TCP caller allowed when reference type opts in",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				Types: map[string]ReferenceTypeAccess{k8sType: {AllowOverTCP: true}},
			}},
			ctx:        tcpContext(),
			caller:     caller,
			ref:        ref(k8sType),
			expectCode: codes.OK,
		},
		{
			name: "TCP caller denied when reference type does not opt in",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				Types: map[string]ReferenceTypeAccess{k8sType: {}},
			}},
			ctx:        tcpContext(),
			caller:     caller,
			ref:        ref(k8sType),
			expectCode: codes.PermissionDenied,
		},
		{
			name:       "TCP caller denied when caller has no policy",
			ctx:        tcpContext(),
			caller:     caller,
			ref:        ref(k8sType),
			expectCode: codes.PermissionDenied,
		},
		{
			name: "wildcard allows any type over UDS",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				AllowAny: true,
			}},
			ctx:        udsContext(),
			caller:     caller,
			ref:        ref(pidType),
			expectCode: codes.OK,
		},
		{
			name: "wildcard allows any type over TCP when it opts in",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				AllowAny:        true,
				AllowAnyOverTCP: true,
			}},
			ctx:        tcpContext(),
			caller:     caller,
			ref:        ref(pidType),
			expectCode: codes.OK,
		},
		{
			name: "wildcard denies TCP by default",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				AllowAny: true,
			}},
			ctx:        tcpContext(),
			caller:     caller,
			ref:        ref(pidType),
			expectCode: codes.PermissionDenied,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := New(Config{
				AllowedReferenceTypesByCaller: tt.byCaller,
			})
			err := s.authorizeReferenceType(tt.ctx, tt.caller, tt.ref)
			if tt.expectCode == codes.OK {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tt.expectCode, status.Code(err))
		})
	}
}

func brokerCallerContext(caller spiffeid.ID) context.Context {
	spiffeURL, _ := url.Parse(caller.String())
	log, _ := test.NewNullLogger()
	ctx := rpccontext.WithLogger(context.Background(), log)
	return peer.NewContext(ctx, &peer.Peer{
		Addr:     &net.UnixAddr{Name: "/tmp/broker.sock", Net: "unix"},
		AuthInfo: credentials.TLSInfo{SPIFFEID: spiffeURL},
	})
}

var _ workloadattestor.Attestor = fakeAttestor{}

type fakeAttestor struct {
	selectors []*common.Selector
	err       error
}

func (a fakeAttestor) Attest(context.Context, int) ([]*common.Selector, error) {
	return a.selectors, a.err
}

func (a fakeAttestor) AttestReference(context.Context, *anypb.Any) ([]*common.Selector, error) {
	return a.selectors, a.err
}

type fakeManager struct {
	manager.Manager

	entries         []*common.RegistrationEntry
	jwtSVIDs        map[string]*client.JWTSVID
	err             error
	subscribeErr    error
	cacheSubscriber *fakeCacheSubscriber
	bundleCache     *cache.BundleCache
}

func (m *fakeManager) MatchingRegistrationEntries([]*common.Selector) []*common.RegistrationEntry {
	return m.entries
}

func (m *fakeManager) FetchJWTSVID(_ context.Context, entry *common.RegistrationEntry, _ []string) (*client.JWTSVID, error) {
	if m.err != nil {
		return nil, m.err
	}
	svid, ok := m.jwtSVIDs[entry.SpiffeId]
	if !ok {
		return nil, errors.New("no SVID for entry")
	}
	return svid, nil
}

func (m *fakeManager) SubscribeToCacheChanges(context.Context, cache.Selectors) (cache.Subscriber[cache.X509WorkloadUpdate], error) {
	if m.subscribeErr != nil {
		return nil, m.subscribeErr
	}
	return m.cacheSubscriber, nil
}

func (m *fakeManager) SubscribeToBundleChanges() *cache.BundleStream {
	return m.bundleCache.SubscribeToBundleChanges()
}

type fakeCacheSubscriber struct {
	ch chan *cache.X509WorkloadUpdate
}

func (s *fakeCacheSubscriber) Updates() <-chan *cache.X509WorkloadUpdate {
	return s.ch
}

func (s *fakeCacheSubscriber) Finish() {}

func TestGetCallerContext(t *testing.T) {
	caller := spiffeid.RequireFromString("spiffe://example.org/broker")

	for _, tt := range []struct {
		name       string
		ctx        context.Context
		expectCode codes.Code
		expectID   spiffeid.ID
	}{
		{
			name:       "no peer in context",
			ctx:        context.Background(),
			expectCode: codes.Unauthenticated,
		},
		{
			name: "peer with no auth info",
			ctx: peer.NewContext(context.Background(), &peer.Peer{
				Addr: &net.UnixAddr{Name: "/tmp/broker.sock", Net: "unix"},
			}),
			expectCode: codes.Unauthenticated,
		},
		{
			name: "auth info is not TLSInfo",
			ctx: peer.NewContext(context.Background(), &peer.Peer{
				Addr:     &net.UnixAddr{Name: "/tmp/broker.sock", Net: "unix"},
				AuthInfo: insecureAuthInfo{},
			}),
			expectCode: codes.Unauthenticated,
		},
		{
			name: "TLSInfo has no SPIFFE ID",
			ctx: peer.NewContext(context.Background(), &peer.Peer{
				Addr:     &net.UnixAddr{Name: "/tmp/broker.sock", Net: "unix"},
				AuthInfo: credentials.TLSInfo{},
			}),
			expectCode: codes.Unauthenticated,
		},
		{
			name:       "valid caller identity",
			ctx:        brokerCallerContext(caller),
			expectCode: codes.OK,
			expectID:   caller,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := New(Config{})
			id, err := s.getCallerContext(tt.ctx)
			if tt.expectCode != codes.OK {
				require.Error(t, err)
				assert.Equal(t, tt.expectCode, status.Code(err))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectID, id)
		})
	}
}

type insecureAuthInfo struct{}

func (insecureAuthInfo) AuthType() string { return "insecure" }

func TestConstructValidSelectorsFromReference(t *testing.T) {
	caller := spiffeid.RequireFromString("spiffe://example.org/broker")
	wantSelectors := []*common.Selector{{Type: "k8s", Value: "ns:default"}}

	for _, tt := range []struct {
		name       string
		ref        *broker.WorkloadReference
		attestErr  error
		expectCode codes.Code
	}{
		{
			name:       "nil reference",
			ref:        nil,
			expectCode: codes.InvalidArgument,
		},
		{
			name:       "attestor returns a status error",
			ref:        &broker.WorkloadReference{Reference: ref(k8sType)},
			attestErr:  status.Error(codes.NotFound, "no such workload"),
			expectCode: codes.NotFound,
		},
		{
			name:       "attestor returns an opaque error",
			ref:        &broker.WorkloadReference{Reference: ref(k8sType)},
			attestErr:  errors.New("boom"),
			expectCode: codes.Unauthenticated,
		},
		{
			name:       "success",
			ref:        &broker.WorkloadReference{Reference: ref(k8sType)},
			expectCode: codes.OK,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			log, _ := test.NewNullLogger()
			s := New(Config{Attestor: fakeAttestor{selectors: wantSelectors, err: tt.attestErr}})

			selectors, err := s.constructValidSelectorsFromReference(brokerCallerContext(caller), log, tt.ref)
			if tt.expectCode != codes.OK {
				require.Error(t, err)
				assert.Equal(t, tt.expectCode, status.Code(err))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, wantSelectors, selectors)
		})
	}
}

func TestComposeX509SVIDBySelectors(t *testing.T) {
	trustDomain := spiffeid.RequireTrustDomainFromString("example.org")
	ca := testca.New(t, trustDomain)
	bundle := ca.Bundle()

	workloadID := spiffeid.RequireFromPath(trustDomain, "/workload")
	adminID := spiffeid.RequireFromPath(trustDomain, "/admin")
	downstreamID := spiffeid.RequireFromPath(trustDomain, "/downstream")

	workloadSVID := ca.CreateX509SVID(workloadID)
	adminSVID := ca.CreateX509SVID(adminID)
	downstreamSVID := ca.CreateX509SVID(downstreamID)

	t.Run("admin and downstream identities are excluded", func(t *testing.T) {
		update := &cache.X509WorkloadUpdate{
			Bundle: bundle,
			Identities: []cache.X509Identity{
				{Entry: &common.RegistrationEntry{SpiffeId: adminID.String(), Admin: true}, SVID: adminSVID.Certificates, PrivateKey: adminSVID.PrivateKey},
				{Entry: &common.RegistrationEntry{SpiffeId: downstreamID.String(), Downstream: true}, SVID: downstreamSVID.Certificates, PrivateKey: downstreamSVID.PrivateKey},
				{Entry: &common.RegistrationEntry{SpiffeId: workloadID.String()}, SVID: workloadSVID.Certificates, PrivateKey: workloadSVID.PrivateKey},
			},
		}

		resp, notAfters, err := composeX509SVIDBySelectors(update)
		require.NoError(t, err)
		require.Len(t, resp.Svids, 1)
		require.Len(t, notAfters, 1)
		assert.Equal(t, workloadID.String(), resp.Svids[0].SpiffeId)
	})

	t.Run("missing SVID is an error", func(t *testing.T) {
		update := &cache.X509WorkloadUpdate{
			Bundle: bundle,
			Identities: []cache.X509Identity{
				{Entry: &common.RegistrationEntry{SpiffeId: workloadID.String()}, SVID: nil, PrivateKey: workloadSVID.PrivateKey},
			},
		}

		_, _, err := composeX509SVIDBySelectors(update)
		assert.Error(t, err)
	})

	t.Run("federated bundles are marshaled", func(t *testing.T) {
		federatedTD := spiffeid.RequireTrustDomainFromString("federated.test")
		federatedBundle := testca.New(t, federatedTD).Bundle()

		update := &cache.X509WorkloadUpdate{
			Bundle: bundle,
			Identities: []cache.X509Identity{
				{Entry: &common.RegistrationEntry{SpiffeId: workloadID.String()}, SVID: workloadSVID.Certificates, PrivateKey: workloadSVID.PrivateKey},
			},
			FederatedBundles: map[spiffeid.TrustDomain]*cache.Bundle{
				federatedTD: federatedBundle,
			},
		}

		resp, _, err := composeX509SVIDBySelectors(update)
		require.NoError(t, err)
		require.Contains(t, resp.FederatedBundles, federatedTD.IDString())
	})
}

type fakeX509SVIDStream struct {
	grpc.ServerStream

	ctx     context.Context
	sentCh  chan *broker.SubscribeToX509SVIDResponse
	sendErr error
}

func (s *fakeX509SVIDStream) Context() context.Context { return s.ctx }

func (s *fakeX509SVIDStream) Send(resp *broker.SubscribeToX509SVIDResponse) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.sentCh <- resp
	return nil
}

func TestSubscribeToX509SVID(t *testing.T) {
	caller := spiffeid.RequireFromString("spiffe://example.org/broker")
	trustDomain := spiffeid.RequireTrustDomainFromString("example.org")
	ca := testca.New(t, trustDomain)
	workloadID := spiffeid.RequireFromPath(trustDomain, "/workload")
	workloadSVID := ca.CreateX509SVID(workloadID)

	t.Run("attestation error", func(t *testing.T) {
		s := New(Config{Attestor: fakeAttestor{err: errors.New("boom")}, Metrics: fakemetrics.New()})
		ctx, cancel := context.WithCancel(brokerCallerContext(caller))
		defer cancel()

		err := s.SubscribeToX509SVID(&broker.SubscribeToX509SVIDRequest{
			Reference: &broker.WorkloadReference{Reference: ref(k8sType)},
		}, &fakeX509SVIDStream{ctx: ctx})
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	t.Run("reference type not allowed for caller", func(t *testing.T) {
		s := New(Config{
			Attestor: fakeAttestor{},
			Metrics:  fakemetrics.New(),
			AllowedReferenceTypesByCaller: map[spiffeid.ID]ReferenceTypePolicy{
				caller: {Types: map[string]ReferenceTypeAccess{pidType: {}}},
			},
		})
		ctx, cancel := context.WithCancel(brokerCallerContext(caller))
		defer cancel()

		err := s.SubscribeToX509SVID(&broker.SubscribeToX509SVIDRequest{
			Reference: &broker.WorkloadReference{Reference: ref(k8sType)},
		}, &fakeX509SVIDStream{ctx: ctx})
		require.Error(t, err)
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})

	t.Run("identity missing SVID returns internal error", func(t *testing.T) {
		update := &cache.X509WorkloadUpdate{
			Bundle: ca.Bundle(),
			Identities: []cache.X509Identity{
				{Entry: &common.RegistrationEntry{SpiffeId: workloadID.String()}, SVID: nil, PrivateKey: workloadSVID.PrivateKey},
			},
		}
		sub := &fakeCacheSubscriber{ch: make(chan *cache.X509WorkloadUpdate, 1)}
		sub.ch <- update

		s := New(Config{
			Attestor: fakeAttestor{},
			Manager:  &fakeManager{cacheSubscriber: sub},
			Metrics:  fakemetrics.New(),
		})

		ctx, cancel := context.WithCancel(brokerCallerContext(caller))
		defer cancel()
		stream := &fakeX509SVIDStream{ctx: ctx, sentCh: make(chan *broker.SubscribeToX509SVIDResponse, 1)}

		err := s.SubscribeToX509SVID(&broker.SubscribeToX509SVIDRequest{
			Reference: &broker.WorkloadReference{Reference: ref(k8sType)},
		}, stream)
		require.Error(t, err)
		assert.Equal(t, codes.Internal, status.Code(err))
	})

	t.Run("subscribe error", func(t *testing.T) {
		wantErr := errors.New("subscribe failed")
		s := New(Config{
			Attestor: fakeAttestor{},
			Manager:  &fakeManager{subscribeErr: wantErr},
			Metrics:  fakemetrics.New(),
		})
		ctx, cancel := context.WithCancel(brokerCallerContext(caller))
		defer cancel()

		err := s.SubscribeToX509SVID(&broker.SubscribeToX509SVIDRequest{
			Reference: &broker.WorkloadReference{Reference: ref(k8sType)},
		}, &fakeX509SVIDStream{ctx: ctx})
		assert.Equal(t, wantErr, err)
	})

	t.Run("sends updates until context is cancelled", func(t *testing.T) {
		update := &cache.X509WorkloadUpdate{
			Bundle: ca.Bundle(),
			Identities: []cache.X509Identity{
				{Entry: &common.RegistrationEntry{SpiffeId: workloadID.String()}, SVID: workloadSVID.Certificates, PrivateKey: workloadSVID.PrivateKey},
			},
		}
		sub := &fakeCacheSubscriber{ch: make(chan *cache.X509WorkloadUpdate, 1)}
		sub.ch <- update

		metrics := fakemetrics.New()
		s := New(Config{
			Attestor: fakeAttestor{},
			Manager:  &fakeManager{cacheSubscriber: sub},
			Metrics:  metrics,
		})

		ctx, cancel := context.WithCancel(brokerCallerContext(caller))
		stream := &fakeX509SVIDStream{ctx: ctx, sentCh: make(chan *broker.SubscribeToX509SVIDResponse, 1)}

		errCh := make(chan error, 1)
		go func() {
			errCh <- s.SubscribeToX509SVID(&broker.SubscribeToX509SVIDRequest{
				Reference: &broker.WorkloadReference{Reference: ref(k8sType)},
			}, stream)
		}()

		resp := <-stream.sentCh
		require.Len(t, resp.Svids, 1)
		assert.Equal(t, workloadID.String(), resp.Svids[0].SpiffeId)

		cancel()
		require.NoError(t, <-errCh)

		assert.Equal(t, []fakemetrics.MetricItem{
			{
				Type:   fakemetrics.MeasureSinceWithLabelsType,
				Key:    []string{telemetry.BrokerAPI, telemetry.SubscribeX509SVIDs, telemetry.FirstUpdate, telemetry.ElapsedTime},
				Val:    0,
				Labels: []telemetry.Label{},
			},
		}, metrics.AllMetrics())
	})

	t.Run("multiple identities in one update", func(t *testing.T) {
		workload2ID := spiffeid.RequireFromPath(trustDomain, "/workload2")
		workload2SVID := ca.CreateX509SVID(workload2ID)

		update := &cache.X509WorkloadUpdate{
			Bundle: ca.Bundle(),
			Identities: []cache.X509Identity{
				{Entry: &common.RegistrationEntry{SpiffeId: workloadID.String()}, SVID: workloadSVID.Certificates, PrivateKey: workloadSVID.PrivateKey},
				{Entry: &common.RegistrationEntry{SpiffeId: workload2ID.String(), Admin: true}, SVID: workload2SVID.Certificates, PrivateKey: workload2SVID.PrivateKey},
			},
		}
		sub := &fakeCacheSubscriber{ch: make(chan *cache.X509WorkloadUpdate, 1)}
		sub.ch <- update

		s := New(Config{
			Attestor: fakeAttestor{},
			Manager:  &fakeManager{cacheSubscriber: sub},
			Metrics:  fakemetrics.New(),
		})

		ctx, cancel := context.WithCancel(brokerCallerContext(caller))
		stream := &fakeX509SVIDStream{ctx: ctx, sentCh: make(chan *broker.SubscribeToX509SVIDResponse, 1)}

		errCh := make(chan error, 1)
		go func() {
			errCh <- s.SubscribeToX509SVID(&broker.SubscribeToX509SVIDRequest{
				Reference: &broker.WorkloadReference{Reference: ref(k8sType)},
			}, stream)
		}()

		resp := <-stream.sentCh
		require.Len(t, resp.Svids, 1)
		assert.Equal(t, workloadID.String(), resp.Svids[0].SpiffeId)

		cancel()
		require.NoError(t, <-errCh)
	})
}

func TestSubscribeToX509Bundles(t *testing.T) {
	caller := spiffeid.RequireFromString("spiffe://example.org/broker")
	trustDomain := spiffeid.RequireTrustDomainFromString("example.org")
	ca := testca.New(t, trustDomain)

	t.Run("attestation error", func(t *testing.T) {
		s := New(Config{Attestor: fakeAttestor{err: errors.New("boom")}})
		ctx, cancel := context.WithCancel(brokerCallerContext(caller))
		defer cancel()

		err := s.SubscribeToX509Bundles(&broker.SubscribeToX509BundlesRequest{
			Reference: &broker.WorkloadReference{Reference: ref(k8sType)},
		}, &fakeX509BundlesStream{ctx: ctx})
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	t.Run("sends bundle updates until context is cancelled", func(t *testing.T) {
		bundleCache := cache.NewBundleCache(trustDomain, ca.Bundle())
		s := New(Config{
			Attestor: fakeAttestor{},
			Manager:  &fakeManager{bundleCache: bundleCache},
		})

		ctx, cancel := context.WithCancel(brokerCallerContext(caller))
		stream := &fakeX509BundlesStream{ctx: ctx, sentCh: make(chan *broker.SubscribeToX509BundlesResponse, 2)}

		errCh := make(chan error, 1)
		go func() {
			errCh <- s.SubscribeToX509Bundles(&broker.SubscribeToX509BundlesRequest{
				Reference: &broker.WorkloadReference{Reference: ref(k8sType)},
			}, stream)
		}()

		first := <-stream.sentCh
		assert.Contains(t, first.Bundles, trustDomain.IDString())

		federatedTD := spiffeid.RequireTrustDomainFromString("federated.test")
		federatedBundle := testca.New(t, federatedTD).Bundle()
		bundleCache.Update(map[spiffeid.TrustDomain]*cache.Bundle{
			trustDomain: ca.Bundle(),
			federatedTD: federatedBundle,
		})

		second := <-stream.sentCh
		assert.Contains(t, second.Bundles, federatedTD.IDString())

		cancel()
		require.NoError(t, <-errCh)
	})
}

type fakeX509BundlesStream struct {
	grpc.ServerStream

	ctx    context.Context
	sentCh chan *broker.SubscribeToX509BundlesResponse
}

func (s *fakeX509BundlesStream) Context() context.Context { return s.ctx }

func (s *fakeX509BundlesStream) Send(resp *broker.SubscribeToX509BundlesResponse) error {
	s.sentCh <- resp
	return nil
}

func TestFetchJWTSVID(t *testing.T) {
	caller := spiffeid.RequireFromString("spiffe://example.org/broker")
	workloadID := "spiffe://example.org/workload"
	workload2ID := "spiffe://example.org/workload2"
	adminID := "spiffe://example.org/admin"
	downstreamID := "spiffe://example.org/downstream"

	jwtSVID := &client.JWTSVID{
		Token:     "jwt-token",
		IssuedAt:  time.Unix(1000, 0),
		ExpiresAt: time.Unix(2000, 0),
	}
	jwtSVID2 := &client.JWTSVID{
		Token:     "jwt-token-2",
		IssuedAt:  time.Unix(1000, 0),
		ExpiresAt: time.Unix(2000, 0),
	}

	for _, tt := range []struct {
		name        string
		audience    []string
		byCaller    map[spiffeid.ID]ReferenceTypePolicy
		attestErr   error
		fetchErr    error
		entries     []*common.RegistrationEntry
		expectCode  codes.Code
		expectSvids []*broker.JWTSVID
	}{
		{
			name:       "missing audience",
			expectCode: codes.InvalidArgument,
		},
		{
			name:       "attestation error",
			audience:   []string{"aud"},
			attestErr:  errors.New("attest failed"),
			expectCode: codes.Unauthenticated,
		},
		{
			name:     "reference type not allowed for caller",
			audience: []string{"aud"},
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{
				caller: {Types: map[string]ReferenceTypeAccess{pidType: {}}},
			},
			expectCode: codes.PermissionDenied,
		},
		{
			name:     "success",
			audience: []string{"aud"},
			entries: []*common.RegistrationEntry{
				{EntryId: "1", SpiffeId: workloadID},
			},
			expectCode: codes.OK,
			expectSvids: []*broker.JWTSVID{
				{SpiffeId: workloadID, Svid: jwtSVID.Token},
			},
		},
		{
			name:     "success with two entries",
			audience: []string{"aud"},
			entries: []*common.RegistrationEntry{
				{EntryId: "1", SpiffeId: workloadID},
				{EntryId: "2", SpiffeId: workload2ID},
			},
			expectCode: codes.OK,
			expectSvids: []*broker.JWTSVID{
				{SpiffeId: workloadID, Svid: jwtSVID.Token},
				{SpiffeId: workload2ID, Svid: jwtSVID2.Token},
			},
		},
		{
			name:     "fetch error",
			audience: []string{"aud"},
			entries: []*common.RegistrationEntry{
				{EntryId: "1", SpiffeId: workloadID},
			},
			fetchErr:   errors.New("fetch failed"),
			expectCode: codes.Unavailable,
		},
		{
			name:     "admin entries are excluded",
			audience: []string{"aud"},
			entries: []*common.RegistrationEntry{
				{EntryId: "1", SpiffeId: adminID, Admin: true},
			},
			expectCode: codes.PermissionDenied,
		},
		{
			name:     "downstream entries are excluded",
			audience: []string{"aud"},
			entries: []*common.RegistrationEntry{
				{EntryId: "1", SpiffeId: downstreamID, Downstream: true},
			},
			expectCode: codes.PermissionDenied,
		},
		{
			name:     "admin and downstream excluded, normal entry returned",
			audience: []string{"aud"},
			entries: []*common.RegistrationEntry{
				{EntryId: "1", SpiffeId: adminID, Admin: true},
				{EntryId: "2", SpiffeId: downstreamID, Downstream: true},
				{EntryId: "3", SpiffeId: workloadID},
			},
			expectCode: codes.OK,
			expectSvids: []*broker.JWTSVID{
				{SpiffeId: workloadID, Svid: jwtSVID.Token},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := New(Config{
				Manager: &fakeManager{
					entries: tt.entries,
					jwtSVIDs: map[string]*client.JWTSVID{
						workloadID:  jwtSVID,
						workload2ID: jwtSVID2,
					},
					err: tt.fetchErr,
				},
				Attestor:                      fakeAttestor{err: tt.attestErr},
				AllowedReferenceTypesByCaller: tt.byCaller,
			})

			resp, err := s.FetchJWTSVID(brokerCallerContext(caller), &broker.FetchJWTSVIDRequest{
				Audience:  tt.audience,
				Reference: &broker.WorkloadReference{Reference: ref(k8sType)},
			})

			if tt.expectCode != codes.OK {
				require.Error(t, err)
				assert.Equal(t, tt.expectCode, status.Code(err))
				assert.Nil(t, resp)
				return
			}

			require.NoError(t, err)
			require.Len(t, resp.Svids, len(tt.expectSvids))
			for i, want := range tt.expectSvids {
				assert.Equal(t, want.SpiffeId, resp.Svids[i].SpiffeId)
				assert.Equal(t, want.Svid, resp.Svids[i].Svid)
			}
		})
	}
}

func TestSubscribeToJWTBundles(t *testing.T) {
	caller := spiffeid.RequireFromString("spiffe://example.org/broker")
	trustDomain := spiffeid.RequireTrustDomainFromString("example.org")
	ca := testca.New(t, trustDomain)

	t.Run("attestation error", func(t *testing.T) {
		s := New(Config{Attestor: fakeAttestor{err: errors.New("boom")}})
		ctx, cancel := context.WithCancel(brokerCallerContext(caller))
		defer cancel()

		err := s.SubscribeToJWTBundles(&broker.SubscribeToJWTBundlesRequest{
			Reference: &broker.WorkloadReference{Reference: ref(k8sType)},
		}, &fakeJWTBundlesStream{ctx: ctx})
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	t.Run("sends JWKS-encoded bundle updates", func(t *testing.T) {
		bundleCache := cache.NewBundleCache(trustDomain, ca.Bundle())
		s := New(Config{
			Attestor: fakeAttestor{},
			Manager:  &fakeManager{bundleCache: bundleCache},
		})

		ctx, cancel := context.WithCancel(brokerCallerContext(caller))
		stream := &fakeJWTBundlesStream{ctx: ctx, sentCh: make(chan *broker.SubscribeToJWTBundlesResponse, 1)}

		errCh := make(chan error, 1)
		go func() {
			errCh <- s.SubscribeToJWTBundles(&broker.SubscribeToJWTBundlesRequest{
				Reference: &broker.WorkloadReference{Reference: ref(k8sType)},
			}, stream)
		}()

		resp := <-stream.sentCh
		wantJWKS, err := bundleutil.Marshal(ca.Bundle(), bundleutil.NoX509SVIDKeys(), bundleutil.StandardJWKS())
		require.NoError(t, err)
		assert.Equal(t, wantJWKS, resp.Bundles[trustDomain.IDString()])

		cancel()
		require.NoError(t, <-errCh)
	})
}

type fakeJWTBundlesStream struct {
	grpc.ServerStream

	ctx    context.Context
	sentCh chan *broker.SubscribeToJWTBundlesResponse
}

func (s *fakeJWTBundlesStream) Context() context.Context { return s.ctx }

func (s *fakeJWTBundlesStream) Send(resp *broker.SubscribeToJWTBundlesResponse) error {
	s.sentCh <- resp
	return nil
}
