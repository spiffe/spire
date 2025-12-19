package endpoints

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	debugv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/debug/v1"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	loggerv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/logger/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/tlspolicy"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/authpolicy"
	"github.com/spiffe/spire/pkg/server/ca/manager"
	"github.com/spiffe/spire/pkg/server/cache/entrycache"
	"github.com/spiffe/spire/pkg/server/cache/nodecache"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/endpoints/bundle"
	"github.com/spiffe/spire/pkg/server/svid"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	testTD                        = spiffeid.RequireTrustDomainFromString("domain.test")
	foreignFederatedTD            = spiffeid.RequireTrustDomainFromString("foreign-domain.test")
	foreignUnfederatedTD          = spiffeid.RequireTrustDomainFromString("foreign-domain-not-federated.test")
	serverID                      = spiffeid.RequireFromPath(testTD, "/spire/server")
	agentID                       = spiffeid.RequireFromPath(testTD, "/spire/agent/foo")
	adminID                       = spiffeid.RequireFromPath(testTD, "/admin")
	foreignAdminID                = spiffeid.RequireFromPath(foreignFederatedTD, "/admin/foreign")
	unauthorizedForeignAdminID    = spiffeid.RequireFromPath(foreignFederatedTD, "/admin/foreign-not-authorized")
	unfederatedForeignAdminID     = spiffeid.RequireFromPath(foreignUnfederatedTD, "/admin/foreign-not-federated")
	unauthenticatedForeignAdminID = spiffeid.RequireFromPath(foreignFederatedTD, "/admin/foreign-not-authenticated")

	downstreamID = spiffeid.RequireFromPath(testTD, "/downstream")
	rateLimit    = RateLimitConfig{
		Attestation: true,
		Signing:     true,
	}
)

func TestNew(t *testing.T) {
	ctx := context.Background()
	tcpAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	localAddr := getLocalAddr(t)
	svidObserver := newSVIDObserver(nil)

	log, _ := test.NewNullLogger()
	metrics := fakemetrics.New()
	ds := fakedatastore.New(t)

	cat := fakeservercatalog.New()
	cat.SetDataStore(ds)

	clk := clock.NewMock(t)

	pe, err := authpolicy.DefaultAuthPolicy(ctx)
	require.NoError(t, err)

	serverCA := fakeserverca.New(t, testTD, nil)

	endpoints, err := New(ctx, Config{
		TCPAddr:          tcpAddr,
		LocalAddr:        localAddr,
		SVIDObserver:     svidObserver,
		TrustDomain:      testTD,
		Catalog:          cat,
		ServerCA:         serverCA,
		BundleEndpoint:   bundle.EndpointConfig{Address: tcpAddr},
		AuthorityManager: &fakeAuthorityManager{},
		Log:              log,
		RootLog:          log,
		Metrics:          metrics,
		RateLimit:        rateLimit,
		Clock:            clk,
		AuthPolicyEngine: pe,
		TLSPolicy: tlspolicy.Policy{
			RequirePQKEM: true,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, tcpAddr, endpoints.TCPAddr)
	assert.Equal(t, localAddr, endpoints.LocalAddr)
	assert.Equal(t, svidObserver, endpoints.SVIDObserver)
	assert.Equal(t, testTD, endpoints.TrustDomain)
	assert.NotNil(t, endpoints.APIServers.AgentServer)
	assert.NotNil(t, endpoints.APIServers.BundleServer)
	assert.NotNil(t, endpoints.APIServers.DebugServer)
	assert.NotNil(t, endpoints.APIServers.EntryServer)
	assert.NotNil(t, endpoints.APIServers.HealthServer)
	assert.NotNil(t, endpoints.APIServers.LoggerServer)
	assert.NotNil(t, endpoints.APIServers.SVIDServer)
	assert.NotNil(t, endpoints.BundleEndpointServer)
	assert.NotNil(t, endpoints.APIServers.LocalAUthorityServer)
	assert.NotNil(t, endpoints.EntryFetcherPruneEventsTask)
	assert.True(t, endpoints.TLSPolicy.RequirePQKEM)
	assert.Equal(t, cat.GetDataStore(), endpoints.DataStore)
	assert.Equal(t, log, endpoints.Log)
	assert.Equal(t, metrics, endpoints.Metrics)
}

func TestNewErrorCreatingAuthorizedEntryFetcher(t *testing.T) {
	ctx := context.Background()
	tcpAddr := &net.TCPAddr{}
	localAddr := getLocalAddr(t)

	svidObserver := newSVIDObserver(nil)

	log, _ := test.NewNullLogger()
	metrics := fakemetrics.New()
	ds := fakedatastore.New(t)
	ds.SetNextError(errors.New("some datastore error"))

	cat := fakeservercatalog.New()
	cat.SetDataStore(ds)

	clk := clock.NewMock(t)

	pe, err := authpolicy.DefaultAuthPolicy(ctx)
	require.NoError(t, err)

	serverCA := fakeserverca.New(t, testTD, nil)

	endpoints, err := New(ctx, Config{
		TCPAddr:          tcpAddr,
		LocalAddr:        localAddr,
		SVIDObserver:     svidObserver,
		TrustDomain:      testTD,
		Catalog:          cat,
		ServerCA:         serverCA,
		BundleEndpoint:   bundle.EndpointConfig{Address: tcpAddr},
		Log:              log,
		Metrics:          metrics,
		RateLimit:        rateLimit,
		Clock:            clk,
		AuthPolicyEngine: pe,
	})

	assert.Error(t, err)
	assert.Nil(t, endpoints)
}

func TestListenAndServe(t *testing.T) {
	ctx := context.Background()
	ca := testca.New(t, testTD)
	federatedCA := testca.New(t, foreignFederatedTD)
	unfederatedCA := testca.New(t, foreignUnfederatedTD)
	serverSVID := ca.CreateX509SVID(serverID)
	agentSVID := ca.CreateX509SVID(agentID)
	adminSVID := ca.CreateX509SVID(adminID)
	foreignAdminSVID := federatedCA.CreateX509SVID(foreignAdminID)
	unauthorizedForeignAdminSVID := federatedCA.CreateX509SVID(unauthorizedForeignAdminID)
	unauthenticatedForeignAdminSVID := unfederatedCA.CreateX509SVID(unauthenticatedForeignAdminID)
	unfederatedForeignAdminSVID := federatedCA.CreateX509SVID(unfederatedForeignAdminID)
	downstreamSVID := ca.CreateX509SVID(downstreamID)

	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	require.NoError(t, listener.Close())

	ds := fakedatastore.New(t)
	log, _ := test.NewNullLogger()
	metrics := fakemetrics.New()

	bundleEndpointServer := newBundleEndpointServer()
	clk := clock.NewMock(t)

	buildCacheFn := func(ctx context.Context) (entrycache.Cache, error) {
		return entrycache.BuildFromDataStore(ctx, testTD.String(), ds)
	}

	// Prime the datastore with the:
	// - bundle used to verify client certificates.
	// - agent attested node information
	// - admin registration entry
	// - downstream registration entry
	prepareDataStore(t, ds, []*testca.CA{ca, federatedCA}, agentSVID)

	ef, err := NewAuthorizedEntryFetcherWithFullCache(context.Background(), buildCacheFn, log, clk, ds, defaultCacheReloadInterval, defaultPruneEventsOlderThan)
	require.NoError(t, err)

	pe, err := authpolicy.DefaultAuthPolicy(ctx)
	require.NoError(t, err)

	nodeCache, err := nodecache.New(ctx, log, ds, clk, true, true)
	require.NoError(t, err)

	endpoints := Endpoints{
		TCPAddr:      listener.Addr().(*net.TCPAddr),
		LocalAddr:    getLocalAddr(t),
		SVIDObserver: newSVIDObserver(serverSVID),
		TrustDomain:  testTD,
		DataStore:    ds,
		BundleCache:  bundle.NewCache(ds, clk),
		APIServers: APIServers{
			AgentServer:          agentServer{},
			BundleServer:         bundleServer{},
			DebugServer:          debugServer{},
			EntryServer:          entryServer{},
			HealthServer:         healthServer{},
			LoggerServer:         loggerServer{},
			SVIDServer:           svidServer{},
			TrustDomainServer:    trustDomainServer{},
			LocalAUthorityServer: localAuthorityServer{},
		},
		BundleEndpointServer:         bundleEndpointServer,
		Log:                          log,
		Metrics:                      metrics,
		RateLimit:                    rateLimit,
		NodeCacheRebuildTask:         nodeCache.PeriodicRebuild,
		EntryFetcherCacheRebuildTask: ef.RunRebuildCacheTask,
		EntryFetcherPruneEventsTask:  ef.PruneEventsTask,
		AuthPolicyEngine:             pe,
		AdminIDs:                     []spiffeid.ID{foreignAdminSVID.ID},
		nodeCache:                    nodeCache,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// Start listening
	errCh := make(chan error)
	go func() {
		errCh <- endpoints.ListenAndServe(ctx)
	}()

	dialTCP := func(tlsConfig *tls.Config) *grpc.ClientConn {
		conn, err := grpc.NewClient(
			endpoints.TCPAddr.String(),
			grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		)
		require.NoError(t, err)
		return conn
	}

	// Await /tmp/spire-test-*/sockets to become available (within 10s)
	// Avoids flaky tests in CI, where we occasionally see failures
	// due to the socket not being ready when first used by the test
	require.Eventually(t, func() bool {
		_, err := os.Stat(endpoints.LocalAddr.String())
		return err == nil
	}, 10*time.Second, 10*time.Millisecond, "socket %q not available", endpoints.LocalAddr.String())

	target, err := util.GetTargetName(endpoints.LocalAddr)
	require.NoError(t, err)

	localConn, err := util.NewGRPCClient(target)
	require.NoError(t, err)
	defer localConn.Close()

	noauthConfig := tlsconfig.TLSClientConfig(ca.X509Bundle(), tlsconfig.AuthorizeID(serverID))
	require.NoError(t, tlspolicy.ApplyPolicy(noauthConfig, endpoints.TLSPolicy))
	noauthConn := dialTCP(noauthConfig)
	defer noauthConn.Close()

	agentConfig := tlsconfig.MTLSClientConfig(agentSVID, ca.X509Bundle(), tlsconfig.AuthorizeID(serverID))
	require.NoError(t, tlspolicy.ApplyPolicy(agentConfig, endpoints.TLSPolicy))
	agentConn := dialTCP(agentConfig)
	defer agentConn.Close()

	adminConfig := tlsconfig.MTLSClientConfig(adminSVID, ca.X509Bundle(), tlsconfig.AuthorizeID(serverID))
	require.NoError(t, tlspolicy.ApplyPolicy(adminConfig, endpoints.TLSPolicy))
	adminConn := dialTCP(adminConfig)
	defer adminConn.Close()

	downstreamConn := dialTCP(tlsconfig.MTLSClientConfig(downstreamSVID, ca.X509Bundle(), tlsconfig.AuthorizeID(serverID)))
	defer downstreamConn.Close()

	federatedAdminConfig := tlsconfig.MTLSClientConfig(foreignAdminSVID, ca.X509Bundle(), tlsconfig.AuthorizeID(serverID))
	require.NoError(t, tlspolicy.ApplyPolicy(federatedAdminConfig, endpoints.TLSPolicy))
	federatedAdminConn := dialTCP(federatedAdminConfig)
	defer federatedAdminConn.Close()

	t.Run("Bad Client SVID", func(t *testing.T) {
		// Create an SVID from a different CA. This ensures that we verify
		// incoming certificates against the trust bundle.
		badSVID := testca.New(t, testTD).CreateX509SVID(agentID)

		tlsConfig := tlsconfig.MTLSClientConfig(badSVID, ca.X509Bundle(), tlsconfig.AuthorizeID(serverID))
		require.NoError(t, tlspolicy.ApplyPolicy(tlsConfig, endpoints.TLSPolicy))

		badConn, err := grpc.NewClient(
			endpoints.TCPAddr.String(),
			grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		)

		require.NoError(t, err)

		// Call an API using the server clientConn to cause gRPC to attempt to dial the server
		healthClient := grpc_health_v1.NewHealthClient(badConn)
		_, err = healthClient.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
		if !assert.Error(t, err, "dialing should have failed") {
			// close the conn if the dialing unexpectedly succeeded
			badConn.Close()
		}
	})

	conns := testConns{
		local:          localConn,
		noAuth:         noauthConn,
		agent:          agentConn,
		admin:          adminConn,
		federatedAdmin: federatedAdminConn,
		downstream:     downstreamConn,
	}

	t.Run("Agent", func(t *testing.T) {
		testAgentAPI(ctx, t, conns)
	})
	t.Run("Debug", func(t *testing.T) {
		testDebugAPI(ctx, t, conns)
	})
	t.Run("Health", func(t *testing.T) {
		testHealthAPI(ctx, t, conns)
	})
	t.Run("Logger", func(t *testing.T) {
		testLoggerAPI(ctx, t, conns)
	})
	t.Run("Bundle", func(t *testing.T) {
		testBundleAPI(ctx, t, conns)
	})
	t.Run("Entry", func(t *testing.T) {
		testEntryAPI(ctx, t, conns)
	})
	t.Run("SVID", func(t *testing.T) {
		testSVIDAPI(ctx, t, conns)
	})
	t.Run("TrustDomain", func(t *testing.T) {
		testTrustDomainAPI(ctx, t, conns)
	})

	t.Run("LocalAuthority", func(t *testing.T) {
		testLocalAuthorityAPI(ctx, t, conns)
	})

	t.Run("Access denied to remote caller", func(t *testing.T) {
		testRemoteCaller(t, target)
	})

	t.Run("Invalidate connection with misconfigured foreign admin caller", func(t *testing.T) {
		unauthenticatedConfig := tlsconfig.MTLSClientConfig(unauthenticatedForeignAdminSVID, ca.X509Bundle(), tlsconfig.AuthorizeID(serverID))
		unauthorizedConfig := tlsconfig.MTLSClientConfig(unauthorizedForeignAdminSVID, ca.X509Bundle(), tlsconfig.AuthorizeID(serverID))
		unfederatedConfig := tlsconfig.MTLSClientConfig(unfederatedForeignAdminSVID, ca.X509Bundle(), tlsconfig.AuthorizeID(serverID))

		for _, config := range []*tls.Config{unauthenticatedConfig, unauthorizedConfig, unfederatedConfig} {
			require.NoError(t, tlspolicy.ApplyPolicy(config, endpoints.TLSPolicy))

			conn, err := grpc.NewClient(endpoints.TCPAddr.String(),
				grpc.WithTransportCredentials(credentials.NewTLS(config)),
			)
			require.NoError(t, err)
			defer conn.Close()

			_, err = entryv1.NewEntryClient(conn).ListEntries(ctx, nil)
			require.Error(t, err)

			// When TLS handshake fails due to invalid certificates, the server
			// terminates the connection, which gRPC reports as Unavailable.
			// We check the gRPC error code rather than OS-specific error messages.
			require.Equal(t, codes.Unavailable, status.Convert(err).Code(), "expected Unavailable status for misconfigured foreign admin caller")
		}
	})

	// Assert that the bundle endpoint server was called to listen and serve
	require.True(t, bundleEndpointServer.Used(), "bundle server was not called to listen and serve")

	// Cancel the context to bring down the endpoints and ensure they shut
	// down cleanly.
	cancel()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(time.Minute):
		require.FailNow(t, "timed out waiting for ListenAndServe to stop")
	}
}

func prepareDataStore(t *testing.T, ds datastore.DataStore, rootCAs []*testca.CA, agentSVID *x509svid.SVID) {
	// Prepare the bundle
	for _, rootCA := range rootCAs {
		_, err := ds.CreateBundle(context.Background(), makeBundle(rootCA))
		require.NoError(t, err)
	}

	// Create the attested node
	_, err := ds.CreateAttestedNode(context.Background(), &common.AttestedNode{
		SpiffeId:         agentID.String(),
		CertSerialNumber: agentSVID.Certificates[0].SerialNumber.String(),
	})
	require.NoError(t, err)

	// Create an admin entry
	_, err = ds.CreateRegistrationEntry(context.Background(), &common.RegistrationEntry{
		ParentId:  agentID.String(),
		SpiffeId:  adminID.String(),
		Selectors: []*common.Selector{{Type: "not", Value: "relevant"}},
		Admin:     true,
	})
	require.NoError(t, err)

	// Create a downstream entry
	_, err = ds.CreateRegistrationEntry(context.Background(), &common.RegistrationEntry{
		ParentId:   agentID.String(),
		SpiffeId:   downstreamID.String(),
		Selectors:  []*common.Selector{{Type: "not", Value: "relevant"}},
		Downstream: true,
	})
	require.NoError(t, err)
}

type testConns struct {
	local          *grpc.ClientConn
	noAuth         *grpc.ClientConn
	agent          *grpc.ClientConn
	admin          *grpc.ClientConn
	federatedAdmin *grpc.ClientConn
	downstream     *grpc.ClientConn
}

func testAgentAPI(ctx context.Context, t *testing.T, conns testConns) {
	t.Run("Local", func(t *testing.T) {
		testAuthorization(ctx, t, agentv1.NewAgentClient(conns.local), map[string]bool{
			"CountAgents":     true,
			"ListAgents":      true,
			"GetAgent":        true,
			"DeleteAgent":     true,
			"BanAgent":        true,
			"AttestAgent":     true,
			"RenewAgent":      false,
			"CreateJoinToken": true,
			"PostStatus":      false,
		})
	})

	t.Run("NoAuth", func(t *testing.T) {
		testAuthorization(ctx, t, agentv1.NewAgentClient(conns.noAuth), map[string]bool{
			"CountAgents":     false,
			"ListAgents":      false,
			"GetAgent":        false,
			"DeleteAgent":     false,
			"BanAgent":        false,
			"AttestAgent":     true,
			"RenewAgent":      false,
			"CreateJoinToken": false,
			"PostStatus":      false,
		})
	})

	t.Run("Agent", func(t *testing.T) {
		testAuthorization(ctx, t, agentv1.NewAgentClient(conns.agent), map[string]bool{
			"CountAgents":     false,
			"ListAgents":      false,
			"GetAgent":        false,
			"DeleteAgent":     false,
			"BanAgent":        false,
			"AttestAgent":     true,
			"RenewAgent":      true,
			"CreateJoinToken": false,
			// TODO: Must be true for agent (#3908)
			"PostStatus": false,
		})
	})

	t.Run("Admin", func(t *testing.T) {
		testAuthorization(ctx, t, agentv1.NewAgentClient(conns.admin), map[string]bool{
			"CountAgents":     true,
			"ListAgents":      true,
			"GetAgent":        true,
			"DeleteAgent":     true,
			"BanAgent":        true,
			"AttestAgent":     true,
			"RenewAgent":      false,
			"CreateJoinToken": true,
			"PostStatus":      false,
		})
	})

	t.Run("Federated Admin", func(t *testing.T) {
		testAuthorization(ctx, t, agentv1.NewAgentClient(conns.federatedAdmin), map[string]bool{
			"CountAgents":     true,
			"ListAgents":      true,
			"GetAgent":        true,
			"DeleteAgent":     true,
			"BanAgent":        true,
			"AttestAgent":     true,
			"RenewAgent":      false,
			"CreateJoinToken": true,
			"PostStatus":      false,
		})
	})

	t.Run("Downstream", func(t *testing.T) {
		testAuthorization(ctx, t, agentv1.NewAgentClient(conns.downstream), map[string]bool{
			"CountAgents":     false,
			"ListAgents":      false,
			"GetAgent":        false,
			"DeleteAgent":     false,
			"BanAgent":        false,
			"AttestAgent":     true,
			"RenewAgent":      false,
			"CreateJoinToken": false,
			"PostStatus":      false,
		})
	})
}

func testHealthAPI(ctx context.Context, t *testing.T, conns testConns) {
	t.Run("Local", func(t *testing.T) {
		testAuthorization(ctx, t, grpc_health_v1.NewHealthClient(conns.local), map[string]bool{
			"Check": true,
			"List":  true,
			"Watch": true,
		})
	})

	t.Run("NoAuth", func(t *testing.T) {
		assertServiceUnavailable(ctx, t, grpc_health_v1.NewHealthClient(conns.noAuth))
	})

	t.Run("Agent", func(t *testing.T) {
		assertServiceUnavailable(ctx, t, grpc_health_v1.NewHealthClient(conns.agent))
	})

	t.Run("Admin", func(t *testing.T) {
		assertServiceUnavailable(ctx, t, grpc_health_v1.NewHealthClient(conns.admin))
	})

	t.Run("Federated Admin", func(t *testing.T) {
		assertServiceUnavailable(ctx, t, grpc_health_v1.NewHealthClient(conns.federatedAdmin))
	})

	t.Run("Downstream", func(t *testing.T) {
		assertServiceUnavailable(ctx, t, grpc_health_v1.NewHealthClient(conns.downstream))
	})
}

func testLoggerAPI(ctx context.Context, t *testing.T, conns testConns) {
	t.Run("Local", func(t *testing.T) {
		testAuthorization(ctx, t, loggerv1.NewLoggerClient(conns.local), map[string]bool{
			"GetLogger":     true,
			"SetLogLevel":   true,
			"ResetLogLevel": true,
		})
	})

	t.Run("NoAuth", func(t *testing.T) {
		assertServiceUnavailable(ctx, t, loggerv1.NewLoggerClient(conns.noAuth))
	})

	t.Run("Agent", func(t *testing.T) {
		assertServiceUnavailable(ctx, t, loggerv1.NewLoggerClient(conns.agent))
	})

	t.Run("Admin", func(t *testing.T) {
		assertServiceUnavailable(ctx, t, loggerv1.NewLoggerClient(conns.admin))
	})

	t.Run("Federated Admin", func(t *testing.T) {
		assertServiceUnavailable(ctx, t, loggerv1.NewLoggerClient(conns.federatedAdmin))
	})

	t.Run("Downstream", func(t *testing.T) {
		assertServiceUnavailable(ctx, t, loggerv1.NewLoggerClient(conns.downstream))
	})
}

func testDebugAPI(ctx context.Context, t *testing.T, conns testConns) {
	t.Run("Local", func(t *testing.T) {
		testAuthorization(ctx, t, debugv1.NewDebugClient(conns.local), map[string]bool{
			"GetInfo": true,
		})
	})

	t.Run("NoAuth", func(t *testing.T) {
		assertServiceUnavailable(ctx, t, debugv1.NewDebugClient(conns.noAuth))
	})

	t.Run("Agent", func(t *testing.T) {
		assertServiceUnavailable(ctx, t, debugv1.NewDebugClient(conns.agent))
	})

	t.Run("Admin", func(t *testing.T) {
		assertServiceUnavailable(ctx, t, debugv1.NewDebugClient(conns.admin))
	})

	t.Run("Federated Admin", func(t *testing.T) {
		assertServiceUnavailable(ctx, t, debugv1.NewDebugClient(conns.federatedAdmin))
	})

	t.Run("Downstream", func(t *testing.T) {
		assertServiceUnavailable(ctx, t, debugv1.NewDebugClient(conns.downstream))
	})
}

func testBundleAPI(ctx context.Context, t *testing.T, conns testConns) {
	t.Run("Local", func(t *testing.T) {
		testAuthorization(ctx, t, bundlev1.NewBundleClient(conns.local), map[string]bool{
			"GetBundle":                  true,
			"AppendBundle":               true,
			"PublishJWTAuthority":        false,
			"PublishWITAuthority":        false,
			"CountBundles":               true,
			"ListFederatedBundles":       true,
			"GetFederatedBundle":         true,
			"BatchCreateFederatedBundle": true,
			"BatchUpdateFederatedBundle": true,
			"BatchSetFederatedBundle":    true,
			"BatchDeleteFederatedBundle": true,
		})
	})

	t.Run("NoAuth", func(t *testing.T) {
		testAuthorization(ctx, t, bundlev1.NewBundleClient(conns.noAuth), map[string]bool{
			"GetBundle":                  true,
			"AppendBundle":               false,
			"PublishJWTAuthority":        false,
			"PublishWITAuthority":        false,
			"CountBundles":               false,
			"ListFederatedBundles":       false,
			"GetFederatedBundle":         false,
			"BatchCreateFederatedBundle": false,
			"BatchUpdateFederatedBundle": false,
			"BatchSetFederatedBundle":    false,
			"BatchDeleteFederatedBundle": false,
		})
	})

	t.Run("Agent", func(t *testing.T) {
		testAuthorization(ctx, t, bundlev1.NewBundleClient(conns.agent), map[string]bool{
			"GetBundle":                  true,
			"AppendBundle":               false,
			"PublishJWTAuthority":        false,
			"PublishWITAuthority":        false,
			"CountBundles":               false,
			"ListFederatedBundles":       false,
			"GetFederatedBundle":         true,
			"BatchCreateFederatedBundle": false,
			"BatchUpdateFederatedBundle": false,
			"BatchSetFederatedBundle":    false,
			"BatchDeleteFederatedBundle": false,
		})
	})

	t.Run("Admin", func(t *testing.T) {
		testAuthorization(ctx, t, bundlev1.NewBundleClient(conns.admin), map[string]bool{
			"GetBundle":                  true,
			"AppendBundle":               true,
			"PublishJWTAuthority":        false,
			"PublishWITAuthority":        false,
			"CountBundles":               true,
			"ListFederatedBundles":       true,
			"GetFederatedBundle":         true,
			"BatchCreateFederatedBundle": true,
			"BatchUpdateFederatedBundle": true,
			"BatchSetFederatedBundle":    true,
			"BatchDeleteFederatedBundle": true,
		})
	})

	t.Run("Federated Admin", func(t *testing.T) {
		testAuthorization(ctx, t, bundlev1.NewBundleClient(conns.federatedAdmin), map[string]bool{
			"GetBundle":                  true,
			"AppendBundle":               true,
			"PublishJWTAuthority":        false,
			"PublishWITAuthority":        false,
			"CountBundles":               true,
			"ListFederatedBundles":       true,
			"GetFederatedBundle":         true,
			"BatchCreateFederatedBundle": true,
			"BatchUpdateFederatedBundle": true,
			"BatchSetFederatedBundle":    true,
			"BatchDeleteFederatedBundle": true,
		})
	})

	t.Run("Downstream", func(t *testing.T) {
		testAuthorization(ctx, t, bundlev1.NewBundleClient(conns.downstream), map[string]bool{
			"GetBundle":                  true,
			"AppendBundle":               false,
			"PublishJWTAuthority":        true,
			"PublishWITAuthority":        true,
			"CountBundles":               false,
			"ListFederatedBundles":       false,
			"GetFederatedBundle":         false,
			"BatchCreateFederatedBundle": false,
			"BatchUpdateFederatedBundle": false,
			"BatchSetFederatedBundle":    false,
			"BatchDeleteFederatedBundle": false,
		})
	})
}

func testEntryAPI(ctx context.Context, t *testing.T, conns testConns) {
	t.Run("Local", func(t *testing.T) {
		testAuthorization(ctx, t, entryv1.NewEntryClient(conns.local), map[string]bool{
			"CountEntries":          true,
			"ListEntries":           true,
			"GetEntry":              true,
			"BatchCreateEntry":      true,
			"BatchUpdateEntry":      true,
			"BatchDeleteEntry":      true,
			"GetAuthorizedEntries":  false,
			"SyncAuthorizedEntries": false,
		})
	})

	t.Run("NoAuth", func(t *testing.T) {
		testAuthorization(ctx, t, entryv1.NewEntryClient(conns.noAuth), map[string]bool{
			"CountEntries":          false,
			"ListEntries":           false,
			"GetEntry":              false,
			"BatchCreateEntry":      false,
			"BatchUpdateEntry":      false,
			"BatchDeleteEntry":      false,
			"GetAuthorizedEntries":  false,
			"SyncAuthorizedEntries": false,
		})
	})

	t.Run("Agent", func(t *testing.T) {
		testAuthorization(ctx, t, entryv1.NewEntryClient(conns.agent), map[string]bool{
			"CountEntries":          false,
			"ListEntries":           false,
			"GetEntry":              false,
			"BatchCreateEntry":      false,
			"BatchUpdateEntry":      false,
			"BatchDeleteEntry":      false,
			"GetAuthorizedEntries":  true,
			"SyncAuthorizedEntries": true,
		})
	})

	t.Run("Admin", func(t *testing.T) {
		testAuthorization(ctx, t, entryv1.NewEntryClient(conns.admin), map[string]bool{
			"CountEntries":          true,
			"ListEntries":           true,
			"GetEntry":              true,
			"BatchCreateEntry":      true,
			"BatchUpdateEntry":      true,
			"BatchDeleteEntry":      true,
			"GetAuthorizedEntries":  false,
			"SyncAuthorizedEntries": false,
		})
	})

	t.Run("Federated Admin", func(t *testing.T) {
		testAuthorization(ctx, t, entryv1.NewEntryClient(conns.federatedAdmin), map[string]bool{
			"CountEntries":          true,
			"ListEntries":           true,
			"GetEntry":              true,
			"BatchCreateEntry":      true,
			"BatchUpdateEntry":      true,
			"BatchDeleteEntry":      true,
			"GetAuthorizedEntries":  false,
			"SyncAuthorizedEntries": false,
		})
	})

	t.Run("Downstream", func(t *testing.T) {
		testAuthorization(ctx, t, entryv1.NewEntryClient(conns.downstream), map[string]bool{
			"CountEntries":          false,
			"ListEntries":           false,
			"GetEntry":              false,
			"BatchCreateEntry":      false,
			"BatchUpdateEntry":      false,
			"BatchDeleteEntry":      false,
			"GetAuthorizedEntries":  false,
			"SyncAuthorizedEntries": false,
		})
	})
}

func testSVIDAPI(ctx context.Context, t *testing.T, conns testConns) {
	t.Run("Local", func(t *testing.T) {
		testAuthorization(ctx, t, svidv1.NewSVIDClient(conns.local), map[string]bool{
			"MintX509SVID":        true,
			"MintJWTSVID":         true,
			"MintWITSVID":         true,
			"BatchNewX509SVID":    false,
			"NewJWTSVID":          false,
			"BatchNewWITSVID":     false,
			"NewDownstreamX509CA": false,
		})
	})

	t.Run("NoAuth", func(t *testing.T) {
		testAuthorization(ctx, t, svidv1.NewSVIDClient(conns.noAuth), map[string]bool{
			"MintX509SVID":        false,
			"MintJWTSVID":         false,
			"MintWITSVID":         false,
			"BatchNewX509SVID":    false,
			"NewJWTSVID":          false,
			"BatchNewWITSVID":     false,
			"NewDownstreamX509CA": false,
		})
	})

	t.Run("Agent", func(t *testing.T) {
		testAuthorization(ctx, t, svidv1.NewSVIDClient(conns.agent), map[string]bool{
			"MintX509SVID":        false,
			"MintJWTSVID":         false,
			"MintWITSVID":         false,
			"BatchNewX509SVID":    true,
			"NewJWTSVID":          true,
			"BatchNewWITSVID":     true,
			"NewDownstreamX509CA": false,
		})
	})

	t.Run("Admin", func(t *testing.T) {
		testAuthorization(ctx, t, svidv1.NewSVIDClient(conns.admin), map[string]bool{
			"MintX509SVID":        true,
			"MintJWTSVID":         true,
			"MintWITSVID":         true,
			"BatchNewX509SVID":    false,
			"NewJWTSVID":          false,
			"BatchNewWITSVID":     false,
			"NewDownstreamX509CA": false,
		})
	})

	t.Run("Federated Admin", func(t *testing.T) {
		testAuthorization(ctx, t, svidv1.NewSVIDClient(conns.federatedAdmin), map[string]bool{
			"MintX509SVID":        true,
			"MintJWTSVID":         true,
			"MintWITSVID":         true,
			"BatchNewX509SVID":    false,
			"NewJWTSVID":          false,
			"BatchNewWITSVID":     false,
			"NewDownstreamX509CA": false,
		})
	})

	t.Run("Downstream", func(t *testing.T) {
		testAuthorization(ctx, t, svidv1.NewSVIDClient(conns.downstream), map[string]bool{
			"MintX509SVID":        false,
			"MintJWTSVID":         false,
			"MintWITSVID":         false,
			"BatchNewX509SVID":    false,
			"NewJWTSVID":          false,
			"BatchNewWITSVID":     false,
			"NewDownstreamX509CA": true,
		})
	})
}

func testTrustDomainAPI(ctx context.Context, t *testing.T, conns testConns) {
	t.Run("Local", func(t *testing.T) {
		testAuthorization(ctx, t, trustdomainv1.NewTrustDomainClient(conns.local), map[string]bool{
			"ListFederationRelationships":       true,
			"GetFederationRelationship":         true,
			"BatchCreateFederationRelationship": true,
			"BatchUpdateFederationRelationship": true,
			"BatchDeleteFederationRelationship": true,
			"RefreshBundle":                     true,
		})
	})

	t.Run("NoAuth", func(t *testing.T) {
		testAuthorization(ctx, t, trustdomainv1.NewTrustDomainClient(conns.noAuth), map[string]bool{
			"ListFederationRelationships":       false,
			"GetFederationRelationship":         false,
			"BatchCreateFederationRelationship": false,
			"BatchUpdateFederationRelationship": false,
			"BatchDeleteFederationRelationship": false,
			"RefreshBundle":                     false,
		})
	})

	t.Run("Agent", func(t *testing.T) {
		testAuthorization(ctx, t, trustdomainv1.NewTrustDomainClient(conns.agent), map[string]bool{
			"ListFederationRelationships":       false,
			"GetFederationRelationship":         false,
			"BatchCreateFederationRelationship": false,
			"BatchUpdateFederationRelationship": false,
			"BatchDeleteFederationRelationship": false,
			"RefreshBundle":                     false,
		})
	})

	t.Run("Admin", func(t *testing.T) {
		testAuthorization(ctx, t, trustdomainv1.NewTrustDomainClient(conns.admin), map[string]bool{
			"ListFederationRelationships":       true,
			"GetFederationRelationship":         true,
			"BatchCreateFederationRelationship": true,
			"BatchUpdateFederationRelationship": true,
			"BatchDeleteFederationRelationship": true,
			"RefreshBundle":                     true,
		})
	})

	t.Run("Federated Admin", func(t *testing.T) {
		testAuthorization(ctx, t, trustdomainv1.NewTrustDomainClient(conns.federatedAdmin), map[string]bool{
			"ListFederationRelationships":       true,
			"GetFederationRelationship":         true,
			"BatchCreateFederationRelationship": true,
			"BatchUpdateFederationRelationship": true,
			"BatchDeleteFederationRelationship": true,
			"RefreshBundle":                     true,
		})
	})

	t.Run("Downstream", func(t *testing.T) {
		testAuthorization(ctx, t, trustdomainv1.NewTrustDomainClient(conns.downstream), map[string]bool{
			"ListFederationRelationships":       false,
			"GetFederationRelationship":         false,
			"BatchCreateFederationRelationship": false,
			"BatchUpdateFederationRelationship": false,
			"BatchDeleteFederationRelationship": false,
			"RefreshBundle":                     false,
		})
	})
}

func testLocalAuthorityAPI(ctx context.Context, t *testing.T, conns testConns) {
	t.Run("Local", func(t *testing.T) {
		testAuthorization(ctx, t, localauthorityv1.NewLocalAuthorityClient(conns.local), map[string]bool{
			"GetJWTAuthorityState":        true,
			"PrepareJWTAuthority":         true,
			"ActivateJWTAuthority":        true,
			"TaintJWTAuthority":           true,
			"RevokeJWTAuthority":          true,
			"GetX509AuthorityState":       true,
			"PrepareX509Authority":        true,
			"ActivateX509Authority":       true,
			"TaintX509Authority":          true,
			"TaintX509UpstreamAuthority":  true,
			"RevokeX509Authority":         true,
			"RevokeX509UpstreamAuthority": true,
			"GetWITAuthorityState":        true,
			"PrepareWITAuthority":         true,
			"ActivateWITAuthority":        true,
			"TaintWITAuthority":           true,
			"RevokeWITAuthority":          true,
		})
	})

	t.Run("NoAuth", func(t *testing.T) {
		testAuthorization(ctx, t, localauthorityv1.NewLocalAuthorityClient(conns.noAuth), map[string]bool{
			"GetJWTAuthorityState":        false,
			"PrepareJWTAuthority":         false,
			"ActivateJWTAuthority":        false,
			"TaintJWTAuthority":           false,
			"RevokeJWTAuthority":          false,
			"GetX509AuthorityState":       false,
			"PrepareX509Authority":        false,
			"ActivateX509Authority":       false,
			"TaintX509Authority":          false,
			"TaintX509UpstreamAuthority":  false,
			"RevokeX509Authority":         false,
			"RevokeX509UpstreamAuthority": false,
			"GetWITAuthorityState":        false,
			"PrepareWITAuthority":         false,
			"ActivateWITAuthority":        false,
			"TaintWITAuthority":           false,
			"RevokeWITAuthority":          false,
		})
	})

	t.Run("Agent", func(t *testing.T) {
		testAuthorization(ctx, t, localauthorityv1.NewLocalAuthorityClient(conns.agent), map[string]bool{
			"GetJWTAuthorityState":        false,
			"PrepareJWTAuthority":         false,
			"ActivateJWTAuthority":        false,
			"TaintJWTAuthority":           false,
			"RevokeJWTAuthority":          false,
			"GetX509AuthorityState":       false,
			"PrepareX509Authority":        false,
			"ActivateX509Authority":       false,
			"TaintX509Authority":          false,
			"TaintX509UpstreamAuthority":  false,
			"RevokeX509Authority":         false,
			"RevokeX509UpstreamAuthority": false,
			"GetWITAuthorityState":        false,
			"PrepareWITAuthority":         false,
			"ActivateWITAuthority":        false,
			"TaintWITAuthority":           false,
			"RevokeWITAuthority":          false,
		})
	})

	t.Run("Admin", func(t *testing.T) {
		testAuthorization(ctx, t, localauthorityv1.NewLocalAuthorityClient(conns.admin), map[string]bool{
			"GetJWTAuthorityState":        true,
			"PrepareJWTAuthority":         true,
			"ActivateJWTAuthority":        true,
			"TaintJWTAuthority":           true,
			"RevokeJWTAuthority":          true,
			"GetX509AuthorityState":       true,
			"PrepareX509Authority":        true,
			"ActivateX509Authority":       true,
			"TaintX509Authority":          true,
			"TaintX509UpstreamAuthority":  true,
			"RevokeX509Authority":         true,
			"RevokeX509UpstreamAuthority": true,
			"GetWITAuthorityState":        true,
			"PrepareWITAuthority":         true,
			"ActivateWITAuthority":        true,
			"TaintWITAuthority":           true,
			"RevokeWITAuthority":          true,
		})
	})

	t.Run("Federated Admin", func(t *testing.T) {
		testAuthorization(ctx, t, localauthorityv1.NewLocalAuthorityClient(conns.federatedAdmin), map[string]bool{
			"GetJWTAuthorityState":        true,
			"PrepareJWTAuthority":         true,
			"ActivateJWTAuthority":        true,
			"TaintJWTAuthority":           true,
			"RevokeJWTAuthority":          true,
			"GetX509AuthorityState":       true,
			"PrepareX509Authority":        true,
			"ActivateX509Authority":       true,
			"TaintX509Authority":          true,
			"TaintX509UpstreamAuthority":  true,
			"RevokeX509Authority":         true,
			"RevokeX509UpstreamAuthority": true,
			"GetWITAuthorityState":        true,
			"PrepareWITAuthority":         true,
			"ActivateWITAuthority":        true,
			"TaintWITAuthority":           true,
			"RevokeWITAuthority":          true,
		})
	})

	t.Run("Downstream", func(t *testing.T) {
		testAuthorization(ctx, t, localauthorityv1.NewLocalAuthorityClient(conns.downstream), map[string]bool{
			"GetJWTAuthorityState":        false,
			"PrepareJWTAuthority":         false,
			"ActivateJWTAuthority":        false,
			"TaintJWTAuthority":           false,
			"RevokeJWTAuthority":          false,
			"GetX509AuthorityState":       false,
			"PrepareX509Authority":        false,
			"ActivateX509Authority":       false,
			"TaintX509Authority":          false,
			"TaintX509UpstreamAuthority":  false,
			"RevokeX509Authority":         false,
			"RevokeX509UpstreamAuthority": false,
			"GetWITAuthorityState":        false,
			"PrepareWITAuthority":         false,
			"ActivateWITAuthority":        false,
			"TaintWITAuthority":           false,
			"RevokeWITAuthority":          false,
		})
	})
}

// testAuthorization issues an RPC for each method on the client interface and
// asserts whether the RPC was authorized or not. If a method is not
// represented in the expectedAuthResults, or a method in expectedAuthResults
// does not belong to the client interface, the test will fail.
func testAuthorization(ctx context.Context, t *testing.T, client any, expectedAuthResults map[string]bool) {
	cv := reflect.ValueOf(client)
	ct := cv.Type()

	for i := range ct.NumMethod() {
		mv := cv.Method(i)
		methodName := ct.Method(i).Name
		t.Run(methodName, func(t *testing.T) {
			// Invoke the RPC and assert the results
			out := callRPC(ctx, t, mv)
			require.Len(t, out, 2, "expected two return values")

			var st *status.Status
			if !out[1].IsNil() {
				err, ok := out[1].Interface().(error)
				require.True(t, ok, "2nd output should have been nil or an error")
				st = status.Convert(err)
			}

			expectAuthResult, ok := expectedAuthResults[methodName]
			require.True(t, ok, "%q does not have an expected result", methodName)
			delete(expectedAuthResults, methodName)

			if expectAuthResult {
				if st.Code() != codes.OK {
					t.Fatalf("should have been authorized; code=%s msg=%s", st.Code(), st.Message())
				}
			} else {
				if st.Code() != codes.PermissionDenied {
					t.Fatalf("should not have been authorized; code=%s msg=%s", st.Code(), st.Message())
				}
			}
		})
	}

	// Assert that each method in the expected results was considered.
	for methodName := range expectedAuthResults {
		t.Errorf("%q had an expected result but is not part of the %T interface", methodName, client)
	}
}

// assertServiceUnavailable issues an RPC for each method on the client interface and
// asserts that the RPC was unavailable.
func assertServiceUnavailable(ctx context.Context, t *testing.T, client any) {
	cv := reflect.ValueOf(client)
	ct := cv.Type()

	for i := range ct.NumMethod() {
		mv := cv.Method(i)
		methodName := ct.Method(i).Name
		t.Run(methodName, func(t *testing.T) {
			// Invoke the RPC and assert the results
			out := callRPC(ctx, t, mv)
			require.Len(t, out, 2, "expected two return values")

			var st *status.Status
			if !out[1].IsNil() {
				err, ok := out[1].Interface().(error)
				require.True(t, ok, "2nd output should have been nil or an error")
				st = status.Convert(err)
			}

			if st.Code() != codes.Unimplemented {
				t.Fatalf("should have been unavailable; code=%s msg=%s", st.Code(), st.Message())
			}
		})
	}
}

// callRPC invokes the RPC and returns the results. For unary RPCs, out will be
// the result of the method on the interface. For streams, it will be the
// result of the first call to Recv().
func callRPC(ctx context.Context, t *testing.T, mv reflect.Value) []reflect.Value {
	mt := mv.Type()

	in := []reflect.Value{reflect.ValueOf(ctx)}

	// If there is more than two input parameters, then we need to provide a
	// request object when invoking.
	if mt.NumIn() > 2 {
		in = append(in, reflect.New(mt.In(1).Elem()))
	}

	out := mv.Call(in)
	require.Len(t, out, 2, "expected two return values from the RPC invocation")
	if mt.Out(0).Kind() == reflect.Interface {
		// Response was a stream. We need to invoke Recv() to get at the
		// real response.

		// Check for error
		require.Nil(t, out[1].Interface(), "should have succeeded getting the stream")

		// Invoke Recv()
		rv := out[0].MethodByName("Recv")
		out = rv.Call([]reflect.Value{})
	}

	return out
}

type bundleEndpointServer struct {
	mtx  sync.Mutex
	used bool
}

func newBundleEndpointServer() *bundleEndpointServer {
	return &bundleEndpointServer{}
}

func (s *bundleEndpointServer) ListenAndServe(context.Context) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.used = true
	return nil
}

func (s *bundleEndpointServer) WaitForListening() {
	// This method is a no-op for the bundle server since it does not have a
	// separate listening hook.
}

func (s *bundleEndpointServer) Used() bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return s.used
}

func makeBundle(ca *testca.CA) *common.Bundle {
	bundle := &common.Bundle{
		TrustDomainId: ca.Bundle().TrustDomain().IDString(),
	}

	for _, x509Authority := range ca.X509Authorities() {
		bundle.RootCas = append(bundle.RootCas, &common.Certificate{
			DerBytes: x509Authority.Raw,
		})
	}
	return bundle
}

type svidObserver struct {
	svid *x509svid.SVID
}

func newSVIDObserver(svid *x509svid.SVID) *svidObserver {
	return &svidObserver{svid: svid}
}

func (o *svidObserver) State() svid.State {
	return svid.State{
		SVID: o.svid.Certificates,
		Key:  o.svid.PrivateKey,
	}
}

type fakeAuthorityManager struct {
	manager.AuthorityManager
}

type agentServer struct {
	agentv1.UnsafeAgentServer
}

func (agentServer) CountAgents(_ context.Context, _ *agentv1.CountAgentsRequest) (*agentv1.CountAgentsResponse, error) {
	return &agentv1.CountAgentsResponse{}, nil
}

func (agentServer) ListAgents(_ context.Context, _ *agentv1.ListAgentsRequest) (*agentv1.ListAgentsResponse, error) {
	return &agentv1.ListAgentsResponse{}, nil
}

func (agentServer) GetAgent(_ context.Context, _ *agentv1.GetAgentRequest) (*types.Agent, error) {
	return &types.Agent{}, nil
}

func (agentServer) DeleteAgent(_ context.Context, _ *agentv1.DeleteAgentRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (agentServer) BanAgent(_ context.Context, _ *agentv1.BanAgentRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (agentServer) AttestAgent(stream agentv1.Agent_AttestAgentServer) error {
	return stream.Send(&agentv1.AttestAgentResponse{})
}

func (agentServer) RenewAgent(_ context.Context, _ *agentv1.RenewAgentRequest) (*agentv1.RenewAgentResponse, error) {
	return &agentv1.RenewAgentResponse{}, nil
}

func (agentServer) CreateJoinToken(_ context.Context, _ *agentv1.CreateJoinTokenRequest) (*types.JoinToken, error) {
	return &types.JoinToken{}, nil
}

func (agentServer) PostStatus(_ context.Context, _ *agentv1.PostStatusRequest) (*agentv1.PostStatusResponse, error) {
	return &agentv1.PostStatusResponse{}, nil
}

type bundleServer struct {
	bundlev1.UnsafeBundleServer
}

// Count bundles.
// The caller must be local or present an admin X509-SVID.
func (bundleServer) CountBundles(_ context.Context, _ *bundlev1.CountBundlesRequest) (*bundlev1.CountBundlesResponse, error) {
	return &bundlev1.CountBundlesResponse{}, nil
}

func (bundleServer) GetBundle(_ context.Context, _ *bundlev1.GetBundleRequest) (*types.Bundle, error) {
	return &types.Bundle{}, nil
}

func (bundleServer) AppendBundle(_ context.Context, _ *bundlev1.AppendBundleRequest) (*types.Bundle, error) {
	return &types.Bundle{}, nil
}

func (bundleServer) PublishJWTAuthority(_ context.Context, _ *bundlev1.PublishJWTAuthorityRequest) (*bundlev1.PublishJWTAuthorityResponse, error) {
	return &bundlev1.PublishJWTAuthorityResponse{}, nil
}

func (bundleServer) PublishWITAuthority(_ context.Context, _ *bundlev1.PublishWITAuthorityRequest) (*bundlev1.PublishWITAuthorityResponse, error) {
	return &bundlev1.PublishWITAuthorityResponse{}, nil
}

func (bundleServer) ListFederatedBundles(_ context.Context, _ *bundlev1.ListFederatedBundlesRequest) (*bundlev1.ListFederatedBundlesResponse, error) {
	return &bundlev1.ListFederatedBundlesResponse{}, nil
}

func (bundleServer) GetFederatedBundle(_ context.Context, _ *bundlev1.GetFederatedBundleRequest) (*types.Bundle, error) {
	return &types.Bundle{}, nil
}

func (bundleServer) BatchCreateFederatedBundle(_ context.Context, _ *bundlev1.BatchCreateFederatedBundleRequest) (*bundlev1.BatchCreateFederatedBundleResponse, error) {
	return &bundlev1.BatchCreateFederatedBundleResponse{}, nil
}

func (bundleServer) BatchUpdateFederatedBundle(_ context.Context, _ *bundlev1.BatchUpdateFederatedBundleRequest) (*bundlev1.BatchUpdateFederatedBundleResponse, error) {
	return &bundlev1.BatchUpdateFederatedBundleResponse{}, nil
}

func (bundleServer) BatchSetFederatedBundle(_ context.Context, _ *bundlev1.BatchSetFederatedBundleRequest) (*bundlev1.BatchSetFederatedBundleResponse, error) {
	return &bundlev1.BatchSetFederatedBundleResponse{}, nil
}

func (bundleServer) BatchDeleteFederatedBundle(_ context.Context, _ *bundlev1.BatchDeleteFederatedBundleRequest) (*bundlev1.BatchDeleteFederatedBundleResponse, error) {
	return &bundlev1.BatchDeleteFederatedBundleResponse{}, nil
}

type debugServer struct {
	debugv1.UnsafeDebugServer
}

func (debugServer) GetInfo(context.Context, *debugv1.GetInfoRequest) (*debugv1.GetInfoResponse, error) {
	return &debugv1.GetInfoResponse{}, nil
}

type entryServer struct {
	entryv1.UnsafeEntryServer
}

func (entryServer) CountEntries(_ context.Context, _ *entryv1.CountEntriesRequest) (*entryv1.CountEntriesResponse, error) {
	return &entryv1.CountEntriesResponse{}, nil
}

func (entryServer) ListEntries(_ context.Context, _ *entryv1.ListEntriesRequest) (*entryv1.ListEntriesResponse, error) {
	return &entryv1.ListEntriesResponse{}, nil
}

func (entryServer) GetEntry(_ context.Context, _ *entryv1.GetEntryRequest) (*types.Entry, error) {
	return &types.Entry{}, nil
}

func (entryServer) BatchCreateEntry(_ context.Context, _ *entryv1.BatchCreateEntryRequest) (*entryv1.BatchCreateEntryResponse, error) {
	return &entryv1.BatchCreateEntryResponse{}, nil
}

func (entryServer) BatchUpdateEntry(_ context.Context, _ *entryv1.BatchUpdateEntryRequest) (*entryv1.BatchUpdateEntryResponse, error) {
	return &entryv1.BatchUpdateEntryResponse{}, nil
}

func (entryServer) BatchDeleteEntry(_ context.Context, _ *entryv1.BatchDeleteEntryRequest) (*entryv1.BatchDeleteEntryResponse, error) {
	return &entryv1.BatchDeleteEntryResponse{}, nil
}

func (entryServer) GetAuthorizedEntries(_ context.Context, _ *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
	return &entryv1.GetAuthorizedEntriesResponse{}, nil
}

func (entryServer) SyncAuthorizedEntries(stream entryv1.Entry_SyncAuthorizedEntriesServer) error {
	return stream.Send(&entryv1.SyncAuthorizedEntriesResponse{})
}

type healthServer struct {
	grpc_health_v1.UnsafeHealthServer
}

func (healthServer) Check(_ context.Context, _ *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	return &grpc_health_v1.HealthCheckResponse{}, nil
}

func (healthServer) Watch(_ *grpc_health_v1.HealthCheckRequest, stream grpc_health_v1.Health_WatchServer) error {
	return stream.Send(&grpc_health_v1.HealthCheckResponse{})
}

func (healthServer) List(context.Context, *grpc_health_v1.HealthListRequest) (*grpc_health_v1.HealthListResponse, error) {
	return &grpc_health_v1.HealthListResponse{}, nil
}

type loggerServer struct {
	loggerv1.UnsafeLoggerServer
}

func (loggerServer) GetLogger(context.Context, *loggerv1.GetLoggerRequest) (*types.Logger, error) {
	return &types.Logger{}, nil
}

func (loggerServer) SetLogLevel(context.Context, *loggerv1.SetLogLevelRequest) (*types.Logger, error) {
	return &types.Logger{}, nil
}

func (loggerServer) ResetLogLevel(context.Context, *loggerv1.ResetLogLevelRequest) (*types.Logger, error) {
	return &types.Logger{}, nil
}

type svidServer struct {
	svidv1.UnsafeSVIDServer
}

func (svidServer) MintX509SVID(_ context.Context, _ *svidv1.MintX509SVIDRequest) (*svidv1.MintX509SVIDResponse, error) {
	return &svidv1.MintX509SVIDResponse{}, nil
}

func (svidServer) MintJWTSVID(_ context.Context, _ *svidv1.MintJWTSVIDRequest) (*svidv1.MintJWTSVIDResponse, error) {
	return &svidv1.MintJWTSVIDResponse{}, nil
}

func (svidServer) MintWITSVID(_ context.Context, _ *svidv1.MintWITSVIDRequest) (*svidv1.MintWITSVIDResponse, error) {
	return &svidv1.MintWITSVIDResponse{}, nil
}

func (svidServer) BatchNewX509SVID(_ context.Context, _ *svidv1.BatchNewX509SVIDRequest) (*svidv1.BatchNewX509SVIDResponse, error) {
	return &svidv1.BatchNewX509SVIDResponse{}, nil
}

func (svidServer) NewJWTSVID(_ context.Context, _ *svidv1.NewJWTSVIDRequest) (*svidv1.NewJWTSVIDResponse, error) {
	return &svidv1.NewJWTSVIDResponse{}, nil
}

func (svidServer) BatchNewWITSVID(_ context.Context, _ *svidv1.BatchNewWITSVIDRequest) (*svidv1.BatchNewWITSVIDResponse, error) {
	return &svidv1.BatchNewWITSVIDResponse{}, nil
}

func (svidServer) NewDownstreamX509CA(_ context.Context, _ *svidv1.NewDownstreamX509CARequest) (*svidv1.NewDownstreamX509CAResponse, error) {
	return &svidv1.NewDownstreamX509CAResponse{}, nil
}

type trustDomainServer struct {
	trustdomainv1.UnsafeTrustDomainServer
}

func (trustDomainServer) ListFederationRelationships(_ context.Context, _ *trustdomainv1.ListFederationRelationshipsRequest) (*trustdomainv1.ListFederationRelationshipsResponse, error) {
	return &trustdomainv1.ListFederationRelationshipsResponse{}, nil
}

func (trustDomainServer) GetFederationRelationship(_ context.Context, _ *trustdomainv1.GetFederationRelationshipRequest) (*types.FederationRelationship, error) {
	return &types.FederationRelationship{}, nil
}

func (trustDomainServer) BatchCreateFederationRelationship(_ context.Context, _ *trustdomainv1.BatchCreateFederationRelationshipRequest) (*trustdomainv1.BatchCreateFederationRelationshipResponse, error) {
	return &trustdomainv1.BatchCreateFederationRelationshipResponse{}, nil
}

func (trustDomainServer) BatchUpdateFederationRelationship(_ context.Context, _ *trustdomainv1.BatchUpdateFederationRelationshipRequest) (*trustdomainv1.BatchUpdateFederationRelationshipResponse, error) {
	return &trustdomainv1.BatchUpdateFederationRelationshipResponse{}, nil
}

func (trustDomainServer) BatchDeleteFederationRelationship(_ context.Context, _ *trustdomainv1.BatchDeleteFederationRelationshipRequest) (*trustdomainv1.BatchDeleteFederationRelationshipResponse, error) {
	return &trustdomainv1.BatchDeleteFederationRelationshipResponse{}, nil
}

func (trustDomainServer) RefreshBundle(_ context.Context, _ *trustdomainv1.RefreshBundleRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

type localAuthorityServer struct {
	localauthorityv1.UnsafeLocalAuthorityServer
}

func (localAuthorityServer) GetJWTAuthorityState(context.Context, *localauthorityv1.GetJWTAuthorityStateRequest) (*localauthorityv1.GetJWTAuthorityStateResponse, error) {
	return &localauthorityv1.GetJWTAuthorityStateResponse{}, nil
}

func (localAuthorityServer) PrepareJWTAuthority(context.Context, *localauthorityv1.PrepareJWTAuthorityRequest) (*localauthorityv1.PrepareJWTAuthorityResponse, error) {
	return &localauthorityv1.PrepareJWTAuthorityResponse{}, nil
}

func (localAuthorityServer) ActivateJWTAuthority(context.Context, *localauthorityv1.ActivateJWTAuthorityRequest) (*localauthorityv1.ActivateJWTAuthorityResponse, error) {
	return &localauthorityv1.ActivateJWTAuthorityResponse{}, nil
}

func (localAuthorityServer) TaintJWTAuthority(context.Context, *localauthorityv1.TaintJWTAuthorityRequest) (*localauthorityv1.TaintJWTAuthorityResponse, error) {
	return &localauthorityv1.TaintJWTAuthorityResponse{}, nil
}

func (localAuthorityServer) RevokeJWTAuthority(context.Context, *localauthorityv1.RevokeJWTAuthorityRequest) (*localauthorityv1.RevokeJWTAuthorityResponse, error) {
	return &localauthorityv1.RevokeJWTAuthorityResponse{}, nil
}

func (localAuthorityServer) GetX509AuthorityState(context.Context, *localauthorityv1.GetX509AuthorityStateRequest) (*localauthorityv1.GetX509AuthorityStateResponse, error) {
	return &localauthorityv1.GetX509AuthorityStateResponse{}, nil
}

func (localAuthorityServer) PrepareX509Authority(context.Context, *localauthorityv1.PrepareX509AuthorityRequest) (*localauthorityv1.PrepareX509AuthorityResponse, error) {
	return &localauthorityv1.PrepareX509AuthorityResponse{}, nil
}

func (localAuthorityServer) ActivateX509Authority(context.Context, *localauthorityv1.ActivateX509AuthorityRequest) (*localauthorityv1.ActivateX509AuthorityResponse, error) {
	return &localauthorityv1.ActivateX509AuthorityResponse{}, nil
}

func (localAuthorityServer) TaintX509Authority(context.Context, *localauthorityv1.TaintX509AuthorityRequest) (*localauthorityv1.TaintX509AuthorityResponse, error) {
	return &localauthorityv1.TaintX509AuthorityResponse{}, nil
}

func (localAuthorityServer) TaintX509UpstreamAuthority(context.Context, *localauthorityv1.TaintX509UpstreamAuthorityRequest) (*localauthorityv1.TaintX509UpstreamAuthorityResponse, error) {
	return &localauthorityv1.TaintX509UpstreamAuthorityResponse{}, nil
}

func (localAuthorityServer) RevokeX509Authority(context.Context, *localauthorityv1.RevokeX509AuthorityRequest) (*localauthorityv1.RevokeX509AuthorityResponse, error) {
	return &localauthorityv1.RevokeX509AuthorityResponse{}, nil
}

func (localAuthorityServer) RevokeX509UpstreamAuthority(context.Context, *localauthorityv1.RevokeX509UpstreamAuthorityRequest) (*localauthorityv1.RevokeX509UpstreamAuthorityResponse, error) {
	return &localauthorityv1.RevokeX509UpstreamAuthorityResponse{}, nil
}

func (localAuthorityServer) GetWITAuthorityState(context.Context, *localauthorityv1.GetWITAuthorityStateRequest) (*localauthorityv1.GetWITAuthorityStateResponse, error) {
	return &localauthorityv1.GetWITAuthorityStateResponse{}, nil
}

func (localAuthorityServer) PrepareWITAuthority(context.Context, *localauthorityv1.PrepareWITAuthorityRequest) (*localauthorityv1.PrepareWITAuthorityResponse, error) {
	return &localauthorityv1.PrepareWITAuthorityResponse{}, nil
}

func (localAuthorityServer) ActivateWITAuthority(context.Context, *localauthorityv1.ActivateWITAuthorityRequest) (*localauthorityv1.ActivateWITAuthorityResponse, error) {
	return &localauthorityv1.ActivateWITAuthorityResponse{}, nil
}

func (localAuthorityServer) TaintWITAuthority(context.Context, *localauthorityv1.TaintWITAuthorityRequest) (*localauthorityv1.TaintWITAuthorityResponse, error) {
	return &localauthorityv1.TaintWITAuthorityResponse{}, nil
}

func (localAuthorityServer) RevokeWITAuthority(context.Context, *localauthorityv1.RevokeWITAuthorityRequest) (*localauthorityv1.RevokeWITAuthorityResponse, error) {
	return &localauthorityv1.RevokeWITAuthorityResponse{}, nil
}
