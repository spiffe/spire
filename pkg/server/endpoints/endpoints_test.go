package endpoints

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"reflect"
	"strings"
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
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/authpolicy"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/cache/entrycache"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/endpoints/bundle"
	"github.com/spiffe/spire/pkg/server/svid"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakehealthchecker"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
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
	healthChecker := fakehealthchecker.New()
	manager := ca.NewManager(ca.ManagerConfig{
		CA:            serverCA,
		Catalog:       cat,
		TrustDomain:   testTD,
		CredBuilder:   serverCA.CredBuilder(),
		CredValidator: serverCA.CredValidator(),
		Dir:           spiretest.TempDir(t),
		Log:           log,
		Metrics:       metrics,
		Clock:         clk,
		HealthChecker: healthChecker,
	})

	endpoints, err := New(ctx, Config{
		TCPAddr:          tcpAddr,
		LocalAddr:        localAddr,
		SVIDObserver:     svidObserver,
		TrustDomain:      testTD,
		Catalog:          cat,
		ServerCA:         serverCA,
		BundleEndpoint:   bundle.EndpointConfig{Address: tcpAddr},
		Manager:          manager,
		Log:              log,
		Metrics:          metrics,
		RateLimit:        rateLimit,
		Clock:            clk,
		AuthPolicyEngine: pe,
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
	assert.NotNil(t, endpoints.APIServers.SVIDServer)
	assert.NotNil(t, endpoints.BundleEndpointServer)
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
	healthChecker := fakehealthchecker.New()
	manager := ca.NewManager(ca.ManagerConfig{
		CA:            serverCA,
		Catalog:       cat,
		TrustDomain:   testTD,
		CredBuilder:   serverCA.CredBuilder(),
		CredValidator: serverCA.CredValidator(),
		Dir:           spiretest.TempDir(t),
		Log:           log,
		Metrics:       metrics,
		Clock:         clk,
		HealthChecker: healthChecker,
	})

	endpoints, err := New(ctx, Config{
		TCPAddr:          tcpAddr,
		LocalAddr:        localAddr,
		SVIDObserver:     svidObserver,
		TrustDomain:      testTD,
		Catalog:          cat,
		ServerCA:         serverCA,
		BundleEndpoint:   bundle.EndpointConfig{Address: tcpAddr},
		Manager:          manager,
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
		return entrycache.BuildFromDataStore(ctx, ds)
	}

	ef, err := NewAuthorizedEntryFetcherWithFullCache(context.Background(), buildCacheFn, log, clk, defaultCacheReloadInterval)
	require.NoError(t, err)

	pe, err := authpolicy.DefaultAuthPolicy(ctx)
	require.NoError(t, err)

	endpoints := Endpoints{
		TCPAddr:      listener.Addr().(*net.TCPAddr),
		LocalAddr:    getLocalAddr(t),
		SVIDObserver: newSVIDObserver(serverSVID),
		TrustDomain:  testTD,
		DataStore:    ds,
		BundleCache:  bundle.NewCache(ds, clk),
		APIServers: APIServers{
			AgentServer:       &agentv1.UnimplementedAgentServer{},
			BundleServer:      &bundlev1.UnimplementedBundleServer{},
			DebugServer:       &debugv1.UnimplementedDebugServer{},
			EntryServer:       &entryv1.UnimplementedEntryServer{},
			HealthServer:      &grpc_health_v1.UnimplementedHealthServer{},
			SVIDServer:        &svidv1.UnimplementedSVIDServer{},
			TrustDomainServer: &trustdomainv1.UnimplementedTrustDomainServer{},
		},
		BundleEndpointServer:         bundleEndpointServer,
		Log:                          log,
		Metrics:                      metrics,
		RateLimit:                    rateLimit,
		EntryFetcherCacheRebuildTask: ef.RunRebuildCacheTask,
		AuthPolicyEngine:             pe,
		AdminIDs:                     []spiffeid.ID{foreignAdminSVID.ID},
	}

	// Prime the datastore with the:
	// - bundle used to verify client certificates.
	// - agent attested node information
	// - admin registration entry
	// - downstream registration entry
	prepareDataStore(t, ds, []*testca.CA{ca, federatedCA}, agentSVID)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// Start listening
	errCh := make(chan error)
	go func() {
		errCh <- endpoints.ListenAndServe(ctx)
	}()

	dialTCP := func(tlsConfig *tls.Config) *grpc.ClientConn {
		conn, err := grpc.DialContext(ctx, endpoints.TCPAddr.String(),
			grpc.WithBlock(),
			grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		)
		require.NoError(t, err)
		return conn
	}

	target, err := util.GetTargetName(endpoints.LocalAddr)
	require.NoError(t, err)

	localConn, err := util.GRPCDialContext(ctx, target, grpc.WithBlock())
	require.NoError(t, err)
	defer localConn.Close()

	noauthConn := dialTCP(tlsconfig.TLSClientConfig(ca.X509Bundle(), tlsconfig.AuthorizeID(serverID)))
	defer noauthConn.Close()

	agentConn := dialTCP(tlsconfig.MTLSClientConfig(agentSVID, ca.X509Bundle(), tlsconfig.AuthorizeID(serverID)))
	defer agentConn.Close()

	adminConn := dialTCP(tlsconfig.MTLSClientConfig(adminSVID, ca.X509Bundle(), tlsconfig.AuthorizeID(serverID)))
	defer adminConn.Close()

	downstreamConn := dialTCP(tlsconfig.MTLSClientConfig(downstreamSVID, ca.X509Bundle(), tlsconfig.AuthorizeID(serverID)))
	defer downstreamConn.Close()

	federatedAdminConn := dialTCP(tlsconfig.MTLSClientConfig(foreignAdminSVID, ca.X509Bundle(), tlsconfig.AuthorizeID(serverID)))
	defer downstreamConn.Close()

	t.Run("Bad Client SVID", func(t *testing.T) {
		// Create an SVID from a different CA. This ensures that we verify
		// incoming certificates against the trust bundle.
		badSVID := testca.New(t, testTD).CreateX509SVID(agentID)
		ctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		badConn, err := grpc.DialContext(ctx, endpoints.TCPAddr.String(), grpc.WithBlock(), grpc.FailOnNonTempDialError(true),
			grpc.WithTransportCredentials(credentials.NewTLS(tlsconfig.MTLSClientConfig(badSVID, ca.X509Bundle(), tlsconfig.AuthorizeID(serverID)))),
		)
		if !assert.Error(t, err, "dialing should have failed") {
			// close the conn if the dialing unexpectedly succeeded
			badConn.Close()
		}
	})

	t.Run("Agent", func(t *testing.T) {
		testAgentAPI(ctx, t, localConn, noauthConn, agentConn, adminConn, federatedAdminConn, downstreamConn)
	})
	t.Run("Debug", func(t *testing.T) {
		testDebugAPI(ctx, t, localConn, noauthConn, agentConn, adminConn, federatedAdminConn, downstreamConn)
	})
	t.Run("Health", func(t *testing.T) {
		testHealthAPI(ctx, t, localConn, noauthConn, agentConn, adminConn, federatedAdminConn, downstreamConn)
	})
	t.Run("Bundle", func(t *testing.T) {
		testBundleAPI(ctx, t, localConn, noauthConn, agentConn, adminConn, federatedAdminConn, downstreamConn)
	})
	t.Run("Entry", func(t *testing.T) {
		testEntryAPI(ctx, t, localConn, noauthConn, agentConn, adminConn, federatedAdminConn, downstreamConn)
	})
	t.Run("SVID", func(t *testing.T) {
		testSVIDAPI(ctx, t, localConn, noauthConn, agentConn, adminConn, federatedAdminConn, downstreamConn)
	})
	t.Run("TrustDomain", func(t *testing.T) {
		testTrustDomainAPI(ctx, t, localConn, noauthConn, agentConn, adminConn, federatedAdminConn, downstreamConn)
	})

	t.Run("Access denied to remote caller", func(t *testing.T) {
		testRemoteCaller(ctx, t, target)
	})

	t.Run("Invalidate connection with misconfigured foreign admin caller", func(t *testing.T) {
		unauthenticatedConfig := tlsconfig.MTLSClientConfig(unauthenticatedForeignAdminSVID, ca.X509Bundle(), tlsconfig.AuthorizeID(serverID))
		unauthorizedConfig := tlsconfig.MTLSClientConfig(unauthorizedForeignAdminSVID, ca.X509Bundle(), tlsconfig.AuthorizeID(serverID))
		unfederatedConfig := tlsconfig.MTLSClientConfig(unfederatedForeignAdminSVID, ca.X509Bundle(), tlsconfig.AuthorizeID(serverID))

		for _, config := range []*tls.Config{unauthenticatedConfig, unauthorizedConfig, unfederatedConfig} {
			conn, err := grpc.DialContext(ctx, endpoints.TCPAddr.String(),
				grpc.WithTransportCredentials(credentials.NewTLS(config)),
			)
			require.NoError(t, err)

			_, err = entryv1.NewEntryClient(conn).ListEntries(ctx, nil)
			require.Error(t, err)

			switch {
			// This message can be returned on macOS
			case strings.Contains(err.Error(), "write: broken pipe"):
			// This message can be returned on Windows
			case strings.Contains(err.Error(), "connection was forcibly closed by the remote host"):
			case strings.Contains(err.Error(), "connection reset by peer"):
			case strings.Contains(err.Error(), "tls: bad certificate"):
				return
			default:
				t.Errorf("expected invalid connection for misconfigured foreign admin caller: %s", err.Error())
			}
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

func testAgentAPI(ctx context.Context, t *testing.T, udsConn, noauthConn, agentConn, adminConn, federatedAdminConn, downstreamConn *grpc.ClientConn) {
	t.Run("UDS", func(t *testing.T) {
		testAuthorization(ctx, t, agentv1.NewAgentClient(udsConn), map[string]bool{
			"CountAgents":     true,
			"ListAgents":      true,
			"GetAgent":        true,
			"DeleteAgent":     true,
			"BanAgent":        true,
			"AttestAgent":     true,
			"RenewAgent":      false,
			"CreateJoinToken": true,
		})
	})

	t.Run("NoAuth", func(t *testing.T) {
		testAuthorization(ctx, t, agentv1.NewAgentClient(noauthConn), map[string]bool{
			"CountAgents":     false,
			"ListAgents":      false,
			"GetAgent":        false,
			"DeleteAgent":     false,
			"BanAgent":        false,
			"AttestAgent":     true,
			"RenewAgent":      false,
			"CreateJoinToken": false,
		})
	})

	t.Run("Agent", func(t *testing.T) {
		testAuthorization(ctx, t, agentv1.NewAgentClient(agentConn), map[string]bool{
			"CountAgents":     false,
			"ListAgents":      false,
			"GetAgent":        false,
			"DeleteAgent":     false,
			"BanAgent":        false,
			"AttestAgent":     true,
			"RenewAgent":      true,
			"CreateJoinToken": false,
		})
	})

	t.Run("Admin", func(t *testing.T) {
		testAuthorization(ctx, t, agentv1.NewAgentClient(adminConn), map[string]bool{
			"CountAgents":     true,
			"ListAgents":      true,
			"GetAgent":        true,
			"DeleteAgent":     true,
			"BanAgent":        true,
			"AttestAgent":     true,
			"RenewAgent":      false,
			"CreateJoinToken": true,
		})
	})

	t.Run("Federated Admin", func(t *testing.T) {
		testAuthorization(ctx, t, agentv1.NewAgentClient(federatedAdminConn), map[string]bool{
			"CountAgents":     true,
			"ListAgents":      true,
			"GetAgent":        true,
			"DeleteAgent":     true,
			"BanAgent":        true,
			"AttestAgent":     true,
			"RenewAgent":      false,
			"CreateJoinToken": true,
		})
	})

	t.Run("Downstream", func(t *testing.T) {
		testAuthorization(ctx, t, agentv1.NewAgentClient(downstreamConn), map[string]bool{
			"CountAgents":     false,
			"ListAgents":      false,
			"GetAgent":        false,
			"DeleteAgent":     false,
			"BanAgent":        false,
			"AttestAgent":     true,
			"RenewAgent":      false,
			"CreateJoinToken": false,
		})
	})
}

func testHealthAPI(ctx context.Context, t *testing.T, udsConn, noauthConn, agentConn, adminConn, federatedAdminConn, downstreamConn *grpc.ClientConn) {
	t.Run("UDS", func(t *testing.T) {
		testAuthorization(ctx, t, grpc_health_v1.NewHealthClient(udsConn), map[string]bool{
			"Check": true,
			"Watch": true,
		})
	})

	t.Run("NoAuth", func(t *testing.T) {
		testAuthorization(ctx, t, grpc_health_v1.NewHealthClient(noauthConn), map[string]bool{
			"Check": true,
			"Watch": true,
		})
	})

	t.Run("Agent", func(t *testing.T) {
		testAuthorization(ctx, t, grpc_health_v1.NewHealthClient(agentConn), map[string]bool{
			"Check": true,
			"Watch": true,
		})
	})

	t.Run("Admin", func(t *testing.T) {
		testAuthorization(ctx, t, grpc_health_v1.NewHealthClient(adminConn), map[string]bool{
			"Check": true,
			"Watch": true,
		})
	})

	t.Run("Federated Admin", func(t *testing.T) {
		testAuthorization(ctx, t, grpc_health_v1.NewHealthClient(federatedAdminConn), map[string]bool{
			"Check": true,
			"Watch": true,
		})
	})

	t.Run("Downstream", func(t *testing.T) {
		testAuthorization(ctx, t, grpc_health_v1.NewHealthClient(downstreamConn), map[string]bool{
			"Check": true,
			"Watch": true,
		})
	})
}

func testDebugAPI(ctx context.Context, t *testing.T, udsConn, noauthConn, agentConn, adminConn, federatedAdminConn, downstreamConn *grpc.ClientConn) {
	t.Run("UDS", func(t *testing.T) {
		testAuthorization(ctx, t, debugv1.NewDebugClient(udsConn), map[string]bool{
			"GetInfo": true,
		})
	})

	t.Run("NoAuth", func(t *testing.T) {
		testAuthorization(ctx, t, debugv1.NewDebugClient(noauthConn), map[string]bool{
			"GetInfo": true,
		})
	})

	t.Run("Agent", func(t *testing.T) {
		testAuthorization(ctx, t, debugv1.NewDebugClient(agentConn), map[string]bool{
			"GetInfo": true,
		})
	})

	t.Run("Admin", func(t *testing.T) {
		testAuthorization(ctx, t, debugv1.NewDebugClient(adminConn), map[string]bool{
			"GetInfo": true,
		})
	})

	t.Run("Federated Admin", func(t *testing.T) {
		testAuthorization(ctx, t, debugv1.NewDebugClient(federatedAdminConn), map[string]bool{
			"GetInfo": true,
		})
	})

	t.Run("Downstream", func(t *testing.T) {
		testAuthorization(ctx, t, debugv1.NewDebugClient(downstreamConn), map[string]bool{
			"GetInfo": true,
		})
	})
}

func testBundleAPI(ctx context.Context, t *testing.T, udsConn, noauthConn, agentConn, adminConn, federatedAdminConn, downstreamConn *grpc.ClientConn) {
	t.Run("UDS", func(t *testing.T) {
		testAuthorization(ctx, t, bundlev1.NewBundleClient(udsConn), map[string]bool{
			"GetBundle":                  true,
			"AppendBundle":               true,
			"PublishJWTAuthority":        false,
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
		testAuthorization(ctx, t, bundlev1.NewBundleClient(noauthConn), map[string]bool{
			"GetBundle":                  true,
			"AppendBundle":               false,
			"PublishJWTAuthority":        false,
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
		testAuthorization(ctx, t, bundlev1.NewBundleClient(agentConn), map[string]bool{
			"GetBundle":                  true,
			"AppendBundle":               false,
			"PublishJWTAuthority":        false,
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
		testAuthorization(ctx, t, bundlev1.NewBundleClient(adminConn), map[string]bool{
			"GetBundle":                  true,
			"AppendBundle":               true,
			"PublishJWTAuthority":        false,
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
		testAuthorization(ctx, t, bundlev1.NewBundleClient(federatedAdminConn), map[string]bool{
			"GetBundle":                  true,
			"AppendBundle":               true,
			"PublishJWTAuthority":        false,
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
		testAuthorization(ctx, t, bundlev1.NewBundleClient(downstreamConn), map[string]bool{
			"GetBundle":                  true,
			"AppendBundle":               false,
			"PublishJWTAuthority":        true,
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

func testEntryAPI(ctx context.Context, t *testing.T, udsConn, noauthConn, agentConn, adminConn, federatedAdminConn, downstreamConn *grpc.ClientConn) {
	t.Run("UDS", func(t *testing.T) {
		testAuthorization(ctx, t, entryv1.NewEntryClient(udsConn), map[string]bool{
			"CountEntries":         true,
			"ListEntries":          true,
			"GetEntry":             true,
			"BatchCreateEntry":     true,
			"BatchUpdateEntry":     true,
			"BatchDeleteEntry":     true,
			"GetAuthorizedEntries": false,
		})
	})

	t.Run("NoAuth", func(t *testing.T) {
		testAuthorization(ctx, t, entryv1.NewEntryClient(noauthConn), map[string]bool{
			"CountEntries":         false,
			"ListEntries":          false,
			"GetEntry":             false,
			"BatchCreateEntry":     false,
			"BatchUpdateEntry":     false,
			"BatchDeleteEntry":     false,
			"GetAuthorizedEntries": false,
		})
	})

	t.Run("Agent", func(t *testing.T) {
		testAuthorization(ctx, t, entryv1.NewEntryClient(agentConn), map[string]bool{
			"CountEntries":         false,
			"ListEntries":          false,
			"GetEntry":             false,
			"BatchCreateEntry":     false,
			"BatchUpdateEntry":     false,
			"BatchDeleteEntry":     false,
			"GetAuthorizedEntries": true,
		})
	})

	t.Run("Admin", func(t *testing.T) {
		testAuthorization(ctx, t, entryv1.NewEntryClient(adminConn), map[string]bool{
			"CountEntries":         true,
			"ListEntries":          true,
			"GetEntry":             true,
			"BatchCreateEntry":     true,
			"BatchUpdateEntry":     true,
			"BatchDeleteEntry":     true,
			"GetAuthorizedEntries": false,
		})
	})

	t.Run("Federated Admin", func(t *testing.T) {
		testAuthorization(ctx, t, entryv1.NewEntryClient(federatedAdminConn), map[string]bool{
			"CountEntries":         true,
			"ListEntries":          true,
			"GetEntry":             true,
			"BatchCreateEntry":     true,
			"BatchUpdateEntry":     true,
			"BatchDeleteEntry":     true,
			"GetAuthorizedEntries": false,
		})
	})

	t.Run("Downstream", func(t *testing.T) {
		testAuthorization(ctx, t, entryv1.NewEntryClient(downstreamConn), map[string]bool{
			"CountEntries":         false,
			"ListEntries":          false,
			"GetEntry":             false,
			"BatchCreateEntry":     false,
			"BatchUpdateEntry":     false,
			"BatchDeleteEntry":     false,
			"GetAuthorizedEntries": false,
		})
	})
}

func testSVIDAPI(ctx context.Context, t *testing.T, udsConn, noauthConn, agentConn, adminConn, federatedAdminConn, downstreamConn *grpc.ClientConn) {
	t.Run("UDS", func(t *testing.T) {
		testAuthorization(ctx, t, svidv1.NewSVIDClient(udsConn), map[string]bool{
			"MintX509SVID":        true,
			"MintJWTSVID":         true,
			"BatchNewX509SVID":    false,
			"NewJWTSVID":          false,
			"NewDownstreamX509CA": false,
		})
	})

	t.Run("NoAuth", func(t *testing.T) {
		testAuthorization(ctx, t, svidv1.NewSVIDClient(noauthConn), map[string]bool{
			"MintX509SVID":        false,
			"MintJWTSVID":         false,
			"BatchNewX509SVID":    false,
			"NewJWTSVID":          false,
			"NewDownstreamX509CA": false,
		})
	})

	t.Run("Agent", func(t *testing.T) {
		testAuthorization(ctx, t, svidv1.NewSVIDClient(agentConn), map[string]bool{
			"MintX509SVID":        false,
			"MintJWTSVID":         false,
			"BatchNewX509SVID":    true,
			"NewJWTSVID":          true,
			"NewDownstreamX509CA": false,
		})
	})

	t.Run("Admin", func(t *testing.T) {
		testAuthorization(ctx, t, svidv1.NewSVIDClient(adminConn), map[string]bool{
			"MintX509SVID":        true,
			"MintJWTSVID":         true,
			"BatchNewX509SVID":    false,
			"NewJWTSVID":          false,
			"NewDownstreamX509CA": false,
		})
	})

	t.Run("Federated Admin", func(t *testing.T) {
		testAuthorization(ctx, t, svidv1.NewSVIDClient(federatedAdminConn), map[string]bool{
			"MintX509SVID":        true,
			"MintJWTSVID":         true,
			"BatchNewX509SVID":    false,
			"NewJWTSVID":          false,
			"NewDownstreamX509CA": false,
		})
	})

	t.Run("Downstream", func(t *testing.T) {
		testAuthorization(ctx, t, svidv1.NewSVIDClient(downstreamConn), map[string]bool{
			"MintX509SVID":        false,
			"MintJWTSVID":         false,
			"BatchNewX509SVID":    false,
			"NewJWTSVID":          false,
			"NewDownstreamX509CA": true,
		})
	})
}

func testTrustDomainAPI(ctx context.Context, t *testing.T, udsConn, noauthConn, agentConn, adminConn, federatedAdminConn, downstreamConn *grpc.ClientConn) {
	t.Run("UDS", func(t *testing.T) {
		testAuthorization(ctx, t, trustdomainv1.NewTrustDomainClient(udsConn), map[string]bool{
			"ListFederationRelationships":       true,
			"GetFederationRelationship":         true,
			"BatchCreateFederationRelationship": true,
			"BatchUpdateFederationRelationship": true,
			"BatchDeleteFederationRelationship": true,
			"RefreshBundle":                     true,
		})
	})

	t.Run("NoAuth", func(t *testing.T) {
		testAuthorization(ctx, t, trustdomainv1.NewTrustDomainClient(noauthConn), map[string]bool{
			"ListFederationRelationships":       false,
			"GetFederationRelationship":         false,
			"BatchCreateFederationRelationship": false,
			"BatchUpdateFederationRelationship": false,
			"BatchDeleteFederationRelationship": false,
			"RefreshBundle":                     false,
		})
	})

	t.Run("Agent", func(t *testing.T) {
		testAuthorization(ctx, t, trustdomainv1.NewTrustDomainClient(agentConn), map[string]bool{
			"ListFederationRelationships":       false,
			"GetFederationRelationship":         false,
			"BatchCreateFederationRelationship": false,
			"BatchUpdateFederationRelationship": false,
			"BatchDeleteFederationRelationship": false,
			"RefreshBundle":                     false,
		})
	})

	t.Run("Admin", func(t *testing.T) {
		testAuthorization(ctx, t, trustdomainv1.NewTrustDomainClient(adminConn), map[string]bool{
			"ListFederationRelationships":       true,
			"GetFederationRelationship":         true,
			"BatchCreateFederationRelationship": true,
			"BatchUpdateFederationRelationship": true,
			"BatchDeleteFederationRelationship": true,
			"RefreshBundle":                     true,
		})
	})

	t.Run("Federated Admin", func(t *testing.T) {
		testAuthorization(ctx, t, trustdomainv1.NewTrustDomainClient(federatedAdminConn), map[string]bool{
			"ListFederationRelationships":       true,
			"GetFederationRelationship":         true,
			"BatchCreateFederationRelationship": true,
			"BatchUpdateFederationRelationship": true,
			"BatchDeleteFederationRelationship": true,
			"RefreshBundle":                     true,
		})
	})

	t.Run("Downstream", func(t *testing.T) {
		testAuthorization(ctx, t, trustdomainv1.NewTrustDomainClient(downstreamConn), map[string]bool{
			"ListFederationRelationships":       false,
			"GetFederationRelationship":         false,
			"BatchCreateFederationRelationship": false,
			"BatchUpdateFederationRelationship": false,
			"BatchDeleteFederationRelationship": false,
			"RefreshBundle":                     false,
		})
	})
}

// testAuthorization makes an RPC for each method on the client interface and
// asserts that the RPC was authorized or not. If a method is not represented
// in the expectedAuthResults, or a method in expectedAuthResults does not
// belong to the client interface, the test will fail.
func testAuthorization(ctx context.Context, t *testing.T, client interface{}, expectedAuthResults map[string]bool) {
	cv := reflect.ValueOf(client)
	ct := cv.Type()

	for i := 0; i < ct.NumMethod(); i++ {
		mv := cv.Method(i)
		methodName := ct.Method(i).Name
		t.Run(methodName, func(t *testing.T) {
			// Invoke the RPC and assert the results
			out := callRPC(ctx, t, mv)
			require.Len(t, out, 2, "expected two return values")
			require.Nil(t, out[0].Interface(), "1st output should have been nil")
			err, ok := out[1].Interface().(error)
			require.True(t, ok, "2nd output should have been an error")

			expectAuthResult, ok := expectedAuthResults[methodName]
			require.True(t, ok, "%q does not have an expected result", methodName)
			delete(expectedAuthResults, methodName)

			st := status.Convert(err)
			if expectAuthResult {
				if st.Code() != codes.Unimplemented {
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

func (s *bundleEndpointServer) ListenAndServe(ctx context.Context) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.used = true
	return nil
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
