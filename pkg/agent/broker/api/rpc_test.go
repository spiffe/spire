package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

var (
	testTrustDomain = spiffeid.RequireTrustDomainFromString("example.org")

	workloadID = spiffeid.RequireFromPath(testTrustDomain, "/workload")
	adminID    = spiffeid.RequireFromPath(testTrustDomain, "/admin")

	brokerID = spiffeid.RequireFromString("spiffe://example.org/service/broker")
)

// harness is what runTest hands to a test body.
type harness struct {
	Client   broker.APIClient
	Attestor *countingAttestor
	Manager  *fakeManager
}

// testParams configures runTest.
type testParams struct {
	// SelectorAssertion is the calling broker's asserted-selector policy. Nil
	// means the broker may not assert selectors.
	SelectorAssertion *SelectorAssertionPolicy

	// AllowedReferenceTypes is the calling broker's reference type policy.
	AllowedReferenceTypes *ReferenceTypePolicy

	// Updates are fed to SubscribeToX509SVID subscribers in order.
	Updates []*cache.X509WorkloadUpdate

	// Entries back MatchingRegistrationEntries.
	Entries []*common.RegistrationEntry

	// JWTSVIDs back FetchJWTSVID, keyed by entry SPIFFE ID.
	JWTSVIDs map[spiffeid.ID]*client.JWTSVID

	// TCP makes the caller appear to have connected over TCP.
	TCP bool

	Metrics *fakemetrics.FakeMetrics
}

// runTest stands the broker API up on a temp UDS socket and hands the callback a
// client.
//
// The real broker endpoint authenticates callers with mTLS and getCallerContext
// reads the peer SPIFFE ID out of credentials.TLSInfo. Standing up a full mTLS
// handshake here would test go-spiffe rather than this service, so an
// interceptor injects an equivalent peer instead. That keeps the caller identity
// and transport (UDS vs TCP) under the test's control.
func runTest(t *testing.T, params testParams, fn func(ctx context.Context, h *harness)) {
	log, _ := test.NewNullLogger()
	log.Level = logrus.DebugLevel

	metrics := params.Metrics
	if metrics == nil {
		metrics = fakemetrics.New()
	}

	fakeManager := &fakeManager{
		updates:  params.Updates,
		entries:  params.Entries,
		jwtSVIDs: params.JWTSVIDs,
	}

	allowedReferenceTypes := map[spiffeid.ID]ReferenceTypePolicy{}
	if params.AllowedReferenceTypes != nil {
		allowedReferenceTypes[brokerID] = *params.AllowedReferenceTypes
	} else {
		allowedReferenceTypes[brokerID] = ReferenceTypePolicy{
			Types: map[string]ReferenceTypeAccess{
				SelectorReferenceTypeURL: {},
				k8sType:                  {},
			},
		}
	}

	selectorAssertion := map[spiffeid.ID]SelectorAssertionPolicy{}
	if params.SelectorAssertion != nil {
		selectorAssertion[brokerID] = *params.SelectorAssertion
	}

	attestor := &countingAttestor{}

	service := New(Config{
		Log:                           log,
		Manager:                       fakeManager,
		Metrics:                       metrics,
		Attestor:                      attestor,
		AllowedReferenceTypesByCaller: allowedReferenceTypes,
		SelectorAssertionByCaller:     selectorAssertion,
	})

	unaryInterceptor, streamInterceptor := middleware.Interceptors(middleware.WithLogger(log))
	server := grpc.NewServer(
		grpc.ChainUnaryInterceptor(injectPeerUnary(brokerID, params.TCP), unaryInterceptor),
		grpc.ChainStreamInterceptor(injectPeerStream(brokerID, params.TCP), streamInterceptor),
	)

	RegisterService(server, service)
	addr := spiretest.ServeGRPCServerOnTempUDSSocket(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	conn, err := grpc.NewClient("unix:"+addr.String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	fn(ctx, &harness{Client: broker.NewAPIClient(conn), Attestor: attestor, Manager: fakeManager})
	cancel()
	server.GracefulStop()
}

// tlsPeerContext builds the peer the real mTLS listener would have produced.
func tlsPeerContext(ctx context.Context, id spiffeid.ID, tcp bool) context.Context {
	u, err := url.Parse(id.String())
	if err != nil {
		panic(err)
	}
	var addr net.Addr = &net.UnixAddr{Name: "/tmp/broker.sock", Net: "unix"}
	if tcp {
		addr = &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}
	}
	return peer.NewContext(ctx, &peer.Peer{
		Addr:     addr,
		AuthInfo: credentials.TLSInfo{SPIFFEID: u},
	})
}

func injectPeerUnary(id spiffeid.ID, tcp bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return handler(tlsPeerContext(ctx, id, tcp), req)
	}
}

func injectPeerStream(id spiffeid.ID, tcp bool) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, &peerServerStream{ServerStream: ss, ctx: tlsPeerContext(ss.Context(), id, tcp)})
	}
}

type peerServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *peerServerStream) Context() context.Context { return s.ctx }

// countingAttestor records whether the workload attestor was consulted. An
// asserted selector reference must never reach it.
type countingAttestor struct {
	attestReferenceCalls atomic.Int32
	selectors            []*common.Selector
	err                  error
}

func (a *countingAttestor) Attest(context.Context, int) ([]*common.Selector, error) {
	return a.selectors, a.err
}

func (a *countingAttestor) AttestReference(context.Context, *anypb.Any) ([]*common.Selector, error) {
	a.attestReferenceCalls.Add(1)
	if a.err != nil {
		return nil, a.err
	}
	return a.selectors, nil
}

func (a *countingAttestor) AttestReferenceCalls() int {
	return int(a.attestReferenceCalls.Load())
}

type fakeManager struct {
	manager.Manager

	updates  []*cache.X509WorkloadUpdate
	entries  []*common.RegistrationEntry
	jwtSVIDs map[spiffeid.ID]*client.JWTSVID

	// lastSelectors records the selectors the service passed down, so tests can
	// assert the asserted set reached the cache verbatim.
	lastSelectors atomic.Pointer[[]*common.Selector]
}

func (m *fakeManager) SubscribeToCacheChanges(_ context.Context, selectors cache.Selectors) (cache.Subscriber[cache.X509WorkloadUpdate], error) {
	captured := []*common.Selector(selectors)
	m.lastSelectors.Store(&captured)
	return newFakeSubscriber(m.updates), nil
}

func (m *fakeManager) MatchingRegistrationEntries(selectors []*common.Selector) []*common.RegistrationEntry {
	captured := selectors
	m.lastSelectors.Store(&captured)
	return m.entries
}

func (m *fakeManager) FetchJWTSVID(_ context.Context, entry *common.RegistrationEntry, _ []string) (*client.JWTSVID, error) {
	id, err := spiffeid.FromString(entry.SpiffeId)
	if err != nil {
		return nil, err
	}
	svid, ok := m.jwtSVIDs[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return svid, nil
}

func (m *fakeManager) LastSelectors() []*common.Selector {
	if p := m.lastSelectors.Load(); p != nil {
		return *p
	}
	return nil
}

type fakeSubscriber struct {
	ch     chan *cache.X509WorkloadUpdate
	cancel context.CancelFunc
}

func newFakeSubscriber(updates []*cache.X509WorkloadUpdate) *fakeSubscriber {
	ch := make(chan *cache.X509WorkloadUpdate)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for _, update := range updates {
			select {
			case ch <- update:
			case <-ctx.Done():
				return
			}
		}
		<-ctx.Done()
	}()
	return &fakeSubscriber{ch: ch, cancel: cancel}
}

func (s *fakeSubscriber) Updates() <-chan *cache.X509WorkloadUpdate { return s.ch }
func (s *fakeSubscriber) Finish()                                   { s.cancel() }

func identityFor(svid *x509svid.SVID, entry *common.RegistrationEntry) cache.X509Identity {
	return cache.X509Identity{
		Entry:      entry,
		PrivateKey: svid.PrivateKey,
		SVID:       svid.Certificates,
	}
}

func entryFor(id spiffeid.ID) *common.RegistrationEntry {
	return &common.RegistrationEntry{EntryId: "entry-" + id.Path(), SpiffeId: id.String()}
}

// selectorReferenceRequest wraps a SelectorReference in a WorkloadReference.
func selectorReferenceRequest(t *testing.T, selectors ...*types.Selector) *broker.WorkloadReference {
	t.Helper()
	return &broker.WorkloadReference{Reference: selectorRef(t, selectors...)}
}

func TestSubscribeToX509SVIDWithSelectorReference(t *testing.T) {
	ca := testca.New(t, testTrustDomain)
	svid := ca.CreateX509SVID(workloadID)

	params := testParams{
		SelectorAssertion: &SelectorAssertionPolicy{
			AllowedSelectorTypes: map[string]struct{}{"k8s_psat": {}},
		},
		Updates: []*cache.X509WorkloadUpdate{
			{
				Bundle:     ca.Bundle(),
				Identities: []cache.X509Identity{identityFor(svid, entryFor(workloadID))},
			},
		},
	}

	runTest(t, params, func(ctx context.Context, h *harness) {
		stream, err := h.Client.SubscribeToX509SVID(ctx, &broker.SubscribeToX509SVIDRequest{
			Reference: selectorReferenceRequest(t, sel("k8s_psat", "ns:default")),
		})
		require.NoError(t, err)

		resp, err := stream.Recv()
		require.NoError(t, err)
		require.Len(t, resp.Svids, 1)
		assert.Equal(t, workloadID.String(), resp.Svids[0].SpiffeId)

		// The whole point of an asserted reference: the agent's workload
		// attestor is never consulted.
		assert.Zero(t, h.Attestor.AttestReferenceCalls())
	})
}

func TestSubscribeToX509SVIDExcludesAdminAndDownstreamEntries(t *testing.T) {
	ca := testca.New(t, testTrustDomain)
	workloadSVID := ca.CreateX509SVID(workloadID)
	adminSVID := ca.CreateX509SVID(adminID)

	adminEntry := entryFor(adminID)
	adminEntry.Admin = true

	params := testParams{
		SelectorAssertion: &SelectorAssertionPolicy{
			AllowedSelectorTypes: map[string]struct{}{"k8s_psat": {}},
		},
		Updates: []*cache.X509WorkloadUpdate{
			{
				Bundle: ca.Bundle(),
				Identities: []cache.X509Identity{
					identityFor(workloadSVID, entryFor(workloadID)),
					identityFor(adminSVID, adminEntry),
				},
			},
		},
	}

	runTest(t, params, func(ctx context.Context, h *harness) {
		stream, err := h.Client.SubscribeToX509SVID(ctx, &broker.SubscribeToX509SVIDRequest{
			Reference: selectorReferenceRequest(t, sel("k8s_psat", "ns:default")),
		})
		require.NoError(t, err)

		resp, err := stream.Recv()
		require.NoError(t, err)
		require.Len(t, resp.Svids, 1)
		assert.Equal(t, workloadID.String(), resp.Svids[0].SpiffeId)
	})
}

func TestFetchJWTSVIDWithSelectorReference(t *testing.T) {
	params := testParams{
		SelectorAssertion: &SelectorAssertionPolicy{
			AllowedSelectorTypes: map[string]struct{}{"k8s_psat": {}},
		},
		Entries: []*common.RegistrationEntry{entryFor(workloadID)},
		JWTSVIDs: map[spiffeid.ID]*client.JWTSVID{
			workloadID: {Token: "token", ExpiresAt: time.Now().Add(time.Hour)},
		},
	}

	runTest(t, params, func(ctx context.Context, h *harness) {
		resp, err := h.Client.FetchJWTSVID(ctx, &broker.FetchJWTSVIDRequest{
			Reference: selectorReferenceRequest(t, sel("k8s_psat", "ns:default")),
			Audience:  []string{"audience"},
		})
		require.NoError(t, err)
		require.Len(t, resp.Svids, 1)
		assert.Equal(t, workloadID.String(), resp.Svids[0].SpiffeId)
		assert.Equal(t, "token", resp.Svids[0].Svid)

		assert.Zero(t, h.Attestor.AttestReferenceCalls())
	})
}

// TestFetchJWTSVIDExcludesAdminAndDownstreamEntries covers the gap where the JWT
// profile did not filter admin/downstream entries while the X.509 profile did,
// which would otherwise let a broker mint a JWT-SVID for an admin identity.
func TestFetchJWTSVIDExcludesAdminAndDownstreamEntries(t *testing.T) {
	adminEntry := entryFor(adminID)
	adminEntry.Admin = true

	downstreamID := spiffeid.RequireFromPath(testTrustDomain, "/downstream")
	downstreamEntry := entryFor(downstreamID)
	downstreamEntry.Downstream = true

	params := testParams{
		SelectorAssertion: &SelectorAssertionPolicy{
			AllowedSelectorTypes: map[string]struct{}{"k8s_psat": {}},
		},
		Entries: []*common.RegistrationEntry{adminEntry, downstreamEntry},
		JWTSVIDs: map[spiffeid.ID]*client.JWTSVID{
			adminID:      {Token: "admin-token", ExpiresAt: time.Now().Add(time.Hour)},
			downstreamID: {Token: "downstream-token", ExpiresAt: time.Now().Add(time.Hour)},
		},
	}

	runTest(t, params, func(ctx context.Context, h *harness) {
		_, err := h.Client.FetchJWTSVID(ctx, &broker.FetchJWTSVIDRequest{
			Reference: selectorReferenceRequest(t, sel("k8s_psat", "ns:default")),
			Audience:  []string{"audience"},
		})
		require.Error(t, err)
		// Both candidate entries were filtered, so nothing was issued.
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})
}

// TestFetchJWTSVIDWithRealisticAssertedSelectorSet exercises the shape
// spire-identity-exchange actually presents: a couple of dozen selectors from a
// single validated token, spanning the plugin's own type plus the exchange's
// stack selector.
func TestFetchJWTSVIDWithRealisticAssertedSelectorSet(t *testing.T) {
	asserted := []*types.Selector{
		sel("github_actions", "repository:example/repo"),
		sel("github_actions", "repository_owner:example"),
		sel("github_actions", "ref:refs/heads/main"),
		sel("github_actions", "sha:0123456789abcdef"),
		sel("github_actions", "workflow:build"),
		sel("github_actions", "environment:prod"),
		sel("github_actions", "runner_environment:github-hosted"),
		sel("spire_identity_exchange", "stack:name:github"),
	}
	for i := range 12 {
		asserted = append(asserted, sel("github_actions", fmt.Sprintf("run_attempt:%d", i)))
	}

	params := testParams{
		SelectorAssertion: &SelectorAssertionPolicy{
			AllowedSelectorTypes: map[string]struct{}{
				"github_actions":          {},
				"spire_identity_exchange": {},
			},
		},
		Entries: []*common.RegistrationEntry{entryFor(workloadID)},
		JWTSVIDs: map[spiffeid.ID]*client.JWTSVID{
			workloadID: {Token: "token", ExpiresAt: time.Now().Add(time.Hour)},
		},
	}

	runTest(t, params, func(ctx context.Context, h *harness) {
		resp, err := h.Client.FetchJWTSVID(ctx, &broker.FetchJWTSVIDRequest{
			Reference: selectorReferenceRequest(t, asserted...),
			Audience:  []string{"audience"},
		})
		require.NoError(t, err)
		require.Len(t, resp.Svids, 1)
		assert.Zero(t, h.Attestor.AttestReferenceCalls())

		// The asserted set must reach the cache verbatim and in order — no
		// reordering, deduplication, or type rewriting on the way through.
		expected := make([]*common.Selector, 0, len(asserted))
		for _, s := range asserted {
			expected = append(expected, &common.Selector{Type: s.GetType(), Value: s.GetValue()})
		}
		spiretest.AssertProtoListEqual(t, expected, h.Manager.LastSelectors())
	})
}

func TestSelectorReferenceDeniedWithoutSelectorAssertionPolicy(t *testing.T) {
	params := testParams{
		// No SelectorAssertion policy configured for this broker.
		Entries: []*common.RegistrationEntry{entryFor(workloadID)},
	}

	runTest(t, params, func(ctx context.Context, h *harness) {
		_, err := h.Client.FetchJWTSVID(ctx, &broker.FetchJWTSVIDRequest{
			Reference: selectorReferenceRequest(t, sel("k8s_psat", "ns:default")),
			Audience:  []string{"audience"},
		})
		require.Error(t, err)
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
		assert.Zero(t, h.Attestor.AttestReferenceCalls())
	})
}

func TestSelectorReferenceDeniedOverTCPByDefault(t *testing.T) {
	params := testParams{
		SelectorAssertion: &SelectorAssertionPolicy{
			AllowedSelectorTypes: map[string]struct{}{"k8s_psat": {}},
		},
		TCP:     true,
		Entries: []*common.RegistrationEntry{entryFor(workloadID)},
	}

	runTest(t, params, func(ctx context.Context, h *harness) {
		_, err := h.Client.FetchJWTSVID(ctx, &broker.FetchJWTSVIDRequest{
			Reference: selectorReferenceRequest(t, sel("k8s_psat", "ns:default")),
			Audience:  []string{"audience"},
		})
		require.Error(t, err)
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})
}

// TestAttestedReferenceStillUsesAttestor guards against the short-circuit
// swallowing the ordinary attested path.
func TestAttestedReferenceStillUsesAttestor(t *testing.T) {
	params := testParams{
		Entries: []*common.RegistrationEntry{entryFor(workloadID)},
		JWTSVIDs: map[spiffeid.ID]*client.JWTSVID{
			workloadID: {Token: "token", ExpiresAt: time.Now().Add(time.Hour)},
		},
	}

	runTest(t, params, func(ctx context.Context, h *harness) {
		h.Attestor.selectors = []*common.Selector{{Type: "k8s", Value: "ns:default"}}

		resp, err := h.Client.FetchJWTSVID(ctx, &broker.FetchJWTSVIDRequest{
			Reference: &broker.WorkloadReference{Reference: &anypb.Any{TypeUrl: k8sType}},
			Audience:  []string{"audience"},
		})
		require.NoError(t, err)
		require.Len(t, resp.Svids, 1)
		assert.Equal(t, 1, h.Attestor.AttestReferenceCalls())
	})
}

func TestReferenceResolutionMetrics(t *testing.T) {
	metrics := fakemetrics.New()
	params := testParams{
		SelectorAssertion: &SelectorAssertionPolicy{
			AllowedSelectorTypes: map[string]struct{}{"k8s_psat": {}},
		},
		Entries: []*common.RegistrationEntry{entryFor(workloadID)},
		JWTSVIDs: map[spiffeid.ID]*client.JWTSVID{
			workloadID: {Token: "token", ExpiresAt: time.Now().Add(time.Hour)},
		},
		Metrics: metrics,
	}

	runTest(t, params, func(ctx context.Context, h *harness) {
		_, err := h.Client.FetchJWTSVID(ctx, &broker.FetchJWTSVIDRequest{
			Reference: selectorReferenceRequest(t, sel("k8s_psat", "ns:default")),
			Audience:  []string{"audience"},
		})
		require.NoError(t, err)
	})

	// The asserted path skips the workload attestor entirely, so this counter
	// is the only way to see it on a dashboard. Label values are sanitized by
	// the metrics layer, which replaces "." and "/" with "_". Derive the
	// expected value from the constant so it cannot drift if the type URL
	// changes.
	sanitizedTypeURL := strings.NewReplacer(".", "_", "/", "_").Replace(SelectorReferenceTypeURL)
	assert.Contains(t, metrics.AllMetrics(), fakemetrics.MetricItem{
		Type: fakemetrics.IncrCounterWithLabelsType,
		Key:  []string{telemetry.BrokerAPI, telemetry.ReferenceResolution},
		Val:  1,
		Labels: []telemetry.Label{
			{Name: telemetry.ReferenceType, Value: sanitizedTypeURL},
			{Name: telemetry.ResolutionMode, Value: telemetry.ResolutionModeAsserted},
		},
	})
}
