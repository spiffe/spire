package endpoints

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire/pkg/common/auth"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/endpoints/bundle"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/pkg/server/svid"
	agentv1 "github.com/spiffe/spire/proto/spire-next/api/server/agent/v1"
	bundlev1 "github.com/spiffe/spire/proto/spire-next/api/server/bundle/v1"
	entryv1 "github.com/spiffe/spire/proto/spire-next/api/server/entry/v1"
	svidv1 "github.com/spiffe/spire/proto/spire-next/api/server/svid/v1"
	"github.com/spiffe/spire/proto/spire/api/node"
	"github.com/spiffe/spire/proto/spire/api/registration"
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
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

var (
	testTD       = spiffeid.RequireTrustDomainFromString("domain.test")
	serverID     = testTD.NewID("/server")
	agentID      = testTD.NewID("/agent")
	adminID      = testTD.NewID("/admin")
	downstreamID = testTD.NewID("/downstream")
)

func TestNew(t *testing.T) {
	tcpAddr := &net.TCPAddr{}
	udsAddr := &net.UnixAddr{}

	svidObserver := newSVIDObserver(nil)

	log, _ := test.NewNullLogger()
	metrics := fakemetrics.New()
	ds := fakedatastore.New(t)

	cat := fakeservercatalog.New()
	cat.SetDataStore(ds)

	dir, err := ioutil.TempDir("", "")
	require.NoError(t, err)
	defer func() {
		os.RemoveAll(dir)
	}()

	clk := clock.NewMock(t)

	serverCA := fakeserverca.New(t, testTD.String(), nil)
	manager := ca.NewManager(ca.ManagerConfig{
		CA:          serverCA,
		Catalog:     cat,
		TrustDomain: *testTD.ID().URL(),
		Dir:         dir,
		Log:         log,
		Metrics:     metrics,
		Clock:       clk,
	})

	endpoints, err := New(Config{
		TCPAddr:               tcpAddr,
		UDSAddr:               udsAddr,
		SVIDObserver:          svidObserver,
		TrustDomain:           testTD,
		Catalog:               cat,
		ServerCA:              serverCA,
		BundleEndpoint:        bundle.EndpointConfig{Address: tcpAddr},
		EnableExperimentalAPI: true,
		Manager:               manager,
		Log:                   log,
		Metrics:               metrics,
	})
	require.NoError(t, err)
	assert.Equal(t, tcpAddr, endpoints.TCPAddr)
	assert.Equal(t, udsAddr, endpoints.UDSAddr)
	assert.Equal(t, svidObserver, endpoints.SVIDObserver)
	assert.Equal(t, testTD, endpoints.TrustDomain)
	assert.NotNil(t, endpoints.RegistrationServer)
	assert.NotNil(t, endpoints.NodeServer)
	if assert.NotNil(t, endpoints.ExperimentalServers) {
		assert.NotNil(t, endpoints.ExperimentalServers.AgentServer)
		assert.NotNil(t, endpoints.ExperimentalServers.BundleServer)
		assert.NotNil(t, endpoints.ExperimentalServers.EntryServer)
		assert.NotNil(t, endpoints.ExperimentalServers.SVIDServer)
	}
	assert.NotNil(t, endpoints.BundleServer)
	assert.Equal(t, cat.GetDataStore(), endpoints.DataStore)
	assert.Equal(t, log, endpoints.Log)
	assert.Equal(t, metrics, endpoints.Metrics)
}

func TestListenAndServe(t *testing.T) {
	ca := testca.New(t, testTD)
	serverSVID := ca.CreateX509SVID(serverID)
	agentSVID := ca.CreateX509SVID(agentID)
	adminSVID := ca.CreateX509SVID(adminID)
	downstreamSVID := ca.CreateX509SVID(downstreamID)

	dir, err := ioutil.TempDir("", "")
	require.NoError(t, err)
	defer func() {
		os.RemoveAll(dir)
	}()

	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	require.NoError(t, listener.Close())

	udsPath := filepath.Join(dir, "socket")

	ds := fakedatastore.New(t)
	log, _ := test.NewNullLogger()
	metrics := fakemetrics.New()

	registrationServer := newRegistrationServer()
	nodeServer := newNodeServer()
	bundleServer := newBundleServer()

	endpoints := Endpoints{
		TCPAddr:            listener.Addr().(*net.TCPAddr),
		UDSAddr:            &net.UnixAddr{Name: udsPath, Net: "unix"},
		SVIDObserver:       newSVIDObserver(serverSVID),
		TrustDomain:        testTD,
		DataStore:          ds,
		RegistrationServer: registrationServer,
		NodeServer:         nodeServer,
		ExperimentalServers: &ExperimentalServers{
			AgentServer:  &agentv1.UnimplementedAgentServer{},
			BundleServer: &bundlev1.UnimplementedBundleServer{},
			EntryServer:  &entryv1.UnimplementedEntryServer{},
			SVIDServer:   &svidv1.UnimplementedSVIDServer{},
		},
		BundleServer: bundleServer,
		Log:          log,
		Metrics:      metrics,
	}

	// Prime the datastore with the:
	// - bundle used to verify client certificates.
	// - agent attested node information
	// - admin registration entry
	// - downstream registration entry
	prepareDataStore(t, ds, ca, agentSVID)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// Start listening
	errCh := make(chan error)
	go func() {
		errCh <- endpoints.ListenAndServe(ctx)
	}()

	dialTCP := func(tlsConfig *tls.Config) *grpc.ClientConn {
		conn, err := grpc.DialContext(ctx, endpoints.TCPAddr.String(),
			grpc.WithBlock(), grpc.FailOnNonTempDialError(true),
			grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		)
		require.NoError(t, err)
		return conn
	}

	udsConn, err := grpc.DialContext(ctx, "unix://"+endpoints.UDSAddr.String(), grpc.WithBlock(), grpc.WithInsecure())
	require.NoError(t, err)
	defer udsConn.Close()

	noauthConn := dialTCP(tlsconfig.TLSClientConfig(ca.X509Bundle(), tlsconfig.AuthorizeID(serverID)))
	defer noauthConn.Close()

	agentConn := dialTCP(tlsconfig.MTLSClientConfig(agentSVID, ca.X509Bundle(), tlsconfig.AuthorizeID(serverID)))
	defer agentConn.Close()

	adminConn := dialTCP(tlsconfig.MTLSClientConfig(adminSVID, ca.X509Bundle(), tlsconfig.AuthorizeID(serverID)))
	defer adminConn.Close()

	downstreamConn := dialTCP(tlsconfig.MTLSClientConfig(downstreamSVID, ca.X509Bundle(), tlsconfig.AuthorizeID(serverID)))
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

	t.Run("Registration", func(t *testing.T) {
		testRegistrationAPI(ctx, t, registrationServer, udsConn, noauthConn, agentConn)
	})
	t.Run("Node", func(t *testing.T) {
		testNodeAPI(ctx, t, nodeServer, udsConn, noauthConn, agentConn)
	})
	t.Run("Agent", func(t *testing.T) {
		testAgentAPI(ctx, t, udsConn, noauthConn, agentConn, adminConn, downstreamConn)
	})
	t.Run("Bundle", func(t *testing.T) {
		testBundleAPI(ctx, t, udsConn, noauthConn, agentConn, adminConn, downstreamConn)
	})
	t.Run("Entry", func(t *testing.T) {
		testEntryAPI(ctx, t, udsConn, noauthConn, agentConn, adminConn, downstreamConn)
	})
	t.Run("SVID", func(t *testing.T) {
		testSVIDAPI(ctx, t, udsConn, noauthConn, agentConn, adminConn, downstreamConn)
	})

	// Assert that the bundle server was called to listen and serve
	require.True(t, bundleServer.Used(), "bundle server was not called to listen and serve")

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

func prepareDataStore(t *testing.T, ds datastore.DataStore, ca *testca.CA, agentSVID *x509svid.SVID) {
	// Prepare the bundle
	_, err := ds.CreateBundle(context.Background(), &datastore.CreateBundleRequest{
		Bundle: makeBundle(ca),
	})
	require.NoError(t, err)

	// Create the attested node
	_, err = ds.CreateAttestedNode(context.Background(), &datastore.CreateAttestedNodeRequest{
		Node: &common.AttestedNode{
			SpiffeId:         agentID.String(),
			CertSerialNumber: agentSVID.Certificates[0].SerialNumber.String(),
		},
	})
	require.NoError(t, err)

	// Create an admin entry
	_, err = ds.CreateRegistrationEntry(context.Background(), &datastore.CreateRegistrationEntryRequest{
		Entry: &common.RegistrationEntry{
			ParentId:  agentID.String(),
			SpiffeId:  adminID.String(),
			Selectors: []*common.Selector{{Type: "not", Value: "relevant"}},
			Admin:     true,
		},
	})
	require.NoError(t, err)

	// Create a downstream entry
	_, err = ds.CreateRegistrationEntry(context.Background(), &datastore.CreateRegistrationEntryRequest{
		Entry: &common.RegistrationEntry{
			ParentId:   agentID.String(),
			SpiffeId:   downstreamID.String(),
			Selectors:  []*common.Selector{{Type: "not", Value: "relevant"}},
			Downstream: true,
		},
	})
	require.NoError(t, err)
}

func testRegistrationAPI(ctx context.Context, t *testing.T, s *registrationServer, udsConn, noauthConn, agentConn *grpc.ClientConn) {
	call := func(t *testing.T, conn *grpc.ClientConn) *peer.Peer {
		peer := doCall(t, s.callTracker, func() error {
			client := registration.NewRegistrationClient(conn)
			_, err := client.GetNodeSelectors(ctx, &registration.GetNodeSelectorsRequest{})
			return err
		})
		require.NotNil(t, peer, "missing peer")
		return peer
	}

	t.Run("UDS", func(t *testing.T) {
		peer := call(t, udsConn)
		require.Equal(t, auth.UntrackedUDSAuthInfo{}, peer.AuthInfo)
	})
	t.Run("TLS", func(t *testing.T) {
		peer := call(t, noauthConn)
		tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
		require.True(t, ok, "peer does not have TLS auth info")
		require.Empty(t, tlsInfo.State.PeerCertificates)
		require.Empty(t, tlsInfo.State.VerifiedChains)
	})
	t.Run("mTLS", func(t *testing.T) {
		peer := call(t, agentConn)
		tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
		require.True(t, ok, "peer does not have TLS auth info")
		require.NotEmpty(t, tlsInfo.State.PeerCertificates)
		require.NotEmpty(t, tlsInfo.State.VerifiedChains)
	})
}

func testNodeAPI(ctx context.Context, t *testing.T, s *nodeServer, udsConn, noauthConn, agentConn *grpc.ClientConn) {
	call := func(t *testing.T, conn *grpc.ClientConn) *peer.Peer {
		return doCall(t, s.callTracker, func() error {
			client := node.NewNodeClient(conn)
			_, err := client.FetchBundle(ctx, &node.FetchBundleRequest{})
			return err
		})
	}
	t.Run("UDS", func(t *testing.T) {
		peer := call(t, udsConn)
		require.Nil(t, peer, "unexpected peer; node API is not served over UDS")
	})
	t.Run("TLS", func(t *testing.T) {
		peer := call(t, noauthConn)
		require.NotNil(t, peer, "missing peer")
		tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
		require.True(t, ok, "peer does not have TLS auth info")
		require.Empty(t, tlsInfo.State.PeerCertificates)
		require.Empty(t, tlsInfo.State.VerifiedChains)
	})
	t.Run("mTLS", func(t *testing.T) {
		peer := call(t, agentConn)
		require.NotNil(t, peer, "missing peer")
		tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
		require.True(t, ok, "peer does not have TLS auth info")
		require.NotEmpty(t, tlsInfo.State.PeerCertificates)
		require.NotEmpty(t, tlsInfo.State.VerifiedChains)
	})
}

func testAgentAPI(ctx context.Context, t *testing.T, udsConn, noauthConn, agentConn, adminConn, downstreamConn *grpc.ClientConn) {
	t.Run("UDS", func(t *testing.T) {
		testAuthorization(ctx, t, agentv1.NewAgentClient(udsConn), map[string]bool{
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

func testBundleAPI(ctx context.Context, t *testing.T, udsConn, noauthConn, agentConn, adminConn, downstreamConn *grpc.ClientConn) {
	t.Run("UDS", func(t *testing.T) {
		testAuthorization(ctx, t, bundlev1.NewBundleClient(udsConn), map[string]bool{
			"GetBundle":                  true,
			"AppendBundle":               true,
			"PublishJWTAuthority":        false,
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
			"ListFederatedBundles":       false,
			"GetFederatedBundle":         false,
			"BatchCreateFederatedBundle": false,
			"BatchUpdateFederatedBundle": false,
			"BatchSetFederatedBundle":    false,
			"BatchDeleteFederatedBundle": false,
		})
	})
}

func testEntryAPI(ctx context.Context, t *testing.T, udsConn, noauthConn, agentConn, adminConn, downstreamConn *grpc.ClientConn) {
	t.Run("UDS", func(t *testing.T) {
		testAuthorization(ctx, t, entryv1.NewEntryClient(udsConn), map[string]bool{
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
			"ListEntries":          false,
			"GetEntry":             false,
			"BatchCreateEntry":     false,
			"BatchUpdateEntry":     false,
			"BatchDeleteEntry":     false,
			"GetAuthorizedEntries": false,
		})
	})
}

func testSVIDAPI(ctx context.Context, t *testing.T, udsConn, noauthConn, agentConn, adminConn, downstreamConn *grpc.ClientConn) {
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

// testAuthorization makes an RPC for each method on the client interface and
// asserts that the RPC was authorized or not. If a method is not represented
// in the expectedAuthResults, or a method in expectedAuthResults does not
// belong to the client interface, the test will fail.
func testAuthorization(ctx context.Context, t *testing.T, client interface{}, expectedAuthResults map[string]bool) {
	cv := reflect.ValueOf(client)
	ct := cv.Type()

	for i := 0; i < ct.NumMethod(); i++ {
		mv := cv.Method(i)
		mt := mv.Type()
		methodName := ct.Method(i).Name
		t.Run(methodName, func(t *testing.T) {
			var out []reflect.Value

			if mv.Type().NumIn() == 2 {
				// server-stream method
				out = mv.Call([]reflect.Value{reflect.ValueOf(ctx)})
				require.Len(t, out, 2)
				// assert there is no failure
				require.Nil(t, out[1].Interface())
				// Now call the Recv() method on the stream
				rv := out[0].MethodByName("Recv")
				out = rv.Call([]reflect.Value{})
			} else {
				// unary method
				out = mv.Call([]reflect.Value{reflect.ValueOf(ctx), reflect.New(mt.In(1).Elem())})
			}

			require.Len(t, out, 2)
			assert.Nil(t, out[0].Interface())
			err, ok := out[1].Interface().(error)
			require.True(t, ok)

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

type registrationServer struct {
	*registration.UnimplementedRegistrationServer
	*callTracker
}

func newRegistrationServer() *registrationServer {
	return &registrationServer{
		callTracker: &callTracker{},
	}
}

type nodeServer struct {
	*node.UnimplementedNodeServer
	*callTracker
}

func newNodeServer() *nodeServer {
	return &nodeServer{
		callTracker: &callTracker{},
	}
}

func doCall(t *testing.T, tracker *callTracker, fn func() error) *peer.Peer {
	tracker.Reset()
	err := fn()
	require.Equal(t, codes.Unimplemented, status.Code(err))
	peers := tracker.Peers()
	switch len(peers) {
	case 0:
		return nil
	case 1:
		return peers[0]
	default:
		require.FailNow(t, "expected zero or one peer", "peers=%d", len(peers))
		return nil // unreachable
	}
}

type callTracker struct {
	mtx   sync.Mutex
	peers []*peer.Peer
}

func (t *callTracker) AuthorizeCall(ctx context.Context, fullMethod string) (context.Context, error) {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Internal, "no peer on context")
	}
	t.peers = append(t.peers, peer)
	return ctx, nil
}

func (t *callTracker) Peers() []*peer.Peer {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	return t.peers
}

func (t *callTracker) Reset() {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	t.peers = nil
}

type bundleServer struct {
	mtx  sync.Mutex
	used bool
}

func newBundleServer() *bundleServer {
	return &bundleServer{}
}

func (s *bundleServer) ListenAndServe(ctx context.Context) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.used = true
	return nil
}

func (s *bundleServer) Used() bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return s.used
}

func makeBundle(ca *testca.CA) *common.Bundle {
	bundle := &common.Bundle{
		TrustDomainId: testTD.IDString(),
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
