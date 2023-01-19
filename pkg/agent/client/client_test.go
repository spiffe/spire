package client

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"
)

var (
	log, _ = test.NewNullLogger()

	trustDomain = spiffeid.RequireTrustDomainFromString("example.org")

	testEntries = []*common.RegistrationEntry{
		{
			EntryId:  "ENTRYID1",
			SpiffeId: "spiffe://example.org/id1",
			Selectors: []*common.Selector{
				{Type: "S", Value: "1"},
			},
			FederatesWith: []string{
				"spiffe://domain1.com",
			},
			RevisionNumber: 1234,
		},
		// This entry should be ignored since it is missing an entry ID
		{
			SpiffeId: "spiffe://example.org/id2",
			Selectors: []*common.Selector{
				{Type: "S", Value: "2"},
			},
			FederatesWith: []string{
				"spiffe://domain2.com",
			},
		},
		// This entry should be ignored since it is missing a SPIFFE ID
		{
			EntryId: "ENTRYID3",
			Selectors: []*common.Selector{
				{Type: "S", Value: "3"},
			},
		},
		// This entry should be ignored since it is missing selectors
		{
			EntryId:  "ENTRYID4",
			SpiffeId: "spiffe://example.org/id4",
		},
	}

	testSvids = map[string]*X509SVID{
		"entry-id": {
			CertChain: []byte{11, 22, 33},
		},
	}

	testBundles = map[string]*common.Bundle{
		"spiffe://example.org": {
			TrustDomainId: "spiffe://example.org",
			RootCas: []*common.Certificate{
				{DerBytes: []byte{10, 20, 30, 40}},
			},
		},
		"spiffe://domain1.com": {
			TrustDomainId: "spiffe://domain1.com",
			RootCas: []*common.Certificate{
				{DerBytes: []byte{10, 20, 30, 40}},
			},
		},
	}
)

func TestFetchUpdates(t *testing.T) {
	client, tc := createClient()

	tc.entryClient.entries = []*types.Entry{
		{
			Id:       "ENTRYID1",
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			SpiffeId: &types.SPIFFEID{
				TrustDomain: "example.org",
				Path:        "/id1",
			},
			Selectors: []*types.Selector{
				{Type: "S", Value: "1"},
			},
			FederatesWith:  []string{"domain1.com"},
			RevisionNumber: 1234,
		},
		// This entry should be ignored since it is missing an entry ID
		{
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			SpiffeId: &types.SPIFFEID{
				TrustDomain: "example.org",
				Path:        "/id2",
			},
			Selectors: []*types.Selector{
				{Type: "S", Value: "2"},
			},
			FederatesWith: []string{"domain2.com"},
		},
		// This entry should be ignored since it is missing a SPIFFE ID
		{
			Id:       "ENTRYID3",
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			Selectors: []*types.Selector{
				{Type: "S", Value: "3"},
			},
		},
		// This entry should be ignored since it is missing selectors
		{
			Id:       "ENTRYID4",
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			SpiffeId: &types.SPIFFEID{
				TrustDomain: "example.org",
				Path:        "/id4",
			},
		},
	}

	tc.svidClient.x509SVIDs = map[string]*types.X509SVID{
		"entry-id": {
			Id:        &types.SPIFFEID{TrustDomain: "example.org", Path: "/path"},
			CertChain: [][]byte{{11, 22, 33}},
		},
	}

	tc.bundleClient.agentBundle = &types.Bundle{
		TrustDomain:     "example.org",
		X509Authorities: []*types.X509Certificate{{Asn1: []byte{10, 20, 30, 40}}},
	}
	tc.bundleClient.federatedBundles = map[string]*types.Bundle{
		"domain1.com": {
			TrustDomain:     "domain1.com",
			X509Authorities: []*types.X509Certificate{{Asn1: []byte{10, 20, 30, 40}}},
		},
		"domain2.com": {
			TrustDomain:     "domain2.com",
			X509Authorities: []*types.X509Certificate{{Asn1: []byte{10, 20, 30, 40}}},
		},
	}

	// Simulate an ongoing SVID rotation (request should not be made in the middle of a rotation)
	client.c.RotMtx.Lock()

	// Do the request in a different go routine
	var wg sync.WaitGroup
	var update *Update
	err := errors.New("a not nil error")
	wg.Add(1)
	go func() {
		defer wg.Done()
		update, err = client.FetchUpdates(context.Background())
	}()

	// The request should wait until the SVID rotation finishes
	require.Contains(t, "a not nil error", err.Error())
	require.Nil(t, update)

	// Simulate the end of the SVID rotation
	client.c.RotMtx.Unlock()
	wg.Wait()

	// Assert results
	require.Nil(t, err)
	assert.Equal(t, testBundles, update.Bundles)
	// Only the first registration entry should be returned since the rest are
	// invalid for one reason or another
	if assert.Len(t, update.Entries, 1) {
		entry := testEntries[0]
		assert.Equal(t, entry, update.Entries[entry.EntryId])
	}
	assertConnectionIsNotNil(t, client)
}

func TestRenewSVID(t *testing.T) {
	client, tc := createClient()

	for _, tt := range []struct {
		name       string
		agentErr   error
		err        string
		expectSVID *X509SVID
		csr        []byte
		agentSVID  *types.X509SVID
	}{
		{
			name: "success",
			csr:  []byte{0, 1, 2},
			agentSVID: &types.X509SVID{
				Id: &types.SPIFFEID{
					TrustDomain: "example.org",
					Path:        "/agent1",
				},
				CertChain: [][]byte{{1, 2, 3}},
				ExpiresAt: 12345,
			},
			expectSVID: &X509SVID{
				CertChain: []byte{1, 2, 3},
				ExpiresAt: 12345,
			},
		},
		{
			name: "no csr",
			csr:  []byte(nil),
			agentSVID: &types.X509SVID{
				Id: &types.SPIFFEID{
					TrustDomain: "example.org",
					Path:        "/agent1",
				},
				CertChain: [][]byte{{1, 2, 3}},
				ExpiresAt: 12345,
			},
			err: "failed to renew agent: malformed param",
		},
		{
			name:     "renew agent fails",
			csr:      []byte{0, 1, 2},
			agentErr: errors.New("renew fails"),
			err:      "failed to renew agent: renew fails",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			tc.agentClient.err = tt.agentErr
			tc.agentClient.svid = tt.agentSVID

			svid, err := client.RenewSVID(context.Background(), tt.csr)
			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				require.Nil(t, svid)
				return
			}

			require.Nil(t, err)
			require.Equal(t, tt.expectSVID, svid)

			assertConnectionIsNotNil(t, client)
		})
	}
}

func TestNewX509SVIDs(t *testing.T) {
	client, tc := createClient()

	tc.entryClient.entries = []*types.Entry{
		{
			Id:       "ENTRYID1",
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			SpiffeId: &types.SPIFFEID{
				TrustDomain: "example.org",
				Path:        "/id1",
			},
			Selectors: []*types.Selector{
				{Type: "S", Value: "1"},
			},
			FederatesWith:  []string{"domain1.com"},
			RevisionNumber: 1234,
		},
		// This entry should be ignored since it is missing an entry ID
		{
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			SpiffeId: &types.SPIFFEID{
				TrustDomain: "example.org",
				Path:        "/id2",
			},
			Selectors: []*types.Selector{
				{Type: "S", Value: "2"},
			},
			FederatesWith: []string{"domain2.com"},
		},
		// This entry should be ignored since it is missing a SPIFFE ID
		{
			Id:       "ENTRYID3",
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			Selectors: []*types.Selector{
				{Type: "S", Value: "3"},
			},
		},
		// This entry should be ignored since it is missing selectors
		{
			Id:       "ENTRYID4",
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			SpiffeId: &types.SPIFFEID{
				TrustDomain: "example.org",
				Path:        "/id4",
			},
		},
	}

	tc.svidClient.x509SVIDs = map[string]*types.X509SVID{
		"entry-id": {
			Id:        &types.SPIFFEID{TrustDomain: "example.org", Path: "/path"},
			CertChain: [][]byte{{11, 22, 33}},
		},
	}

	// Simulate an ongoing SVID rotation (request should not be made in the middle of a rotation)
	client.c.RotMtx.Lock()

	// Do the request in a different go routine
	var wg sync.WaitGroup
	var svids map[string]*X509SVID
	err := errors.New("a not nil error")
	wg.Add(1)
	go func() {
		defer wg.Done()
		svids, err = client.NewX509SVIDs(context.Background(), newTestCSRs())
	}()

	// The request should wait until the SVID rotation finishes
	require.Contains(t, "a not nil error", err.Error())
	require.Nil(t, svids)

	// Simulate the end of the SVID rotation
	client.c.RotMtx.Unlock()
	wg.Wait()

	// Assert results
	require.Nil(t, err)
	assert.Equal(t, testSvids, svids)
	assertConnectionIsNotNil(t, client)
}

func newTestCSRs() map[string][]byte {
	return map[string][]byte{
		"entry-id": {1, 2, 3, 4},
	}
}

func TestFetchReleaseWaitsForFetchUpdatesToFinish(t *testing.T) {
	client, tc := createClient()

	tc.entryClient.entries = []*types.Entry{
		{
			Id:       "ENTRYID1",
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			SpiffeId: &types.SPIFFEID{
				TrustDomain: "example.org",
				Path:        "/id1",
			},
			Selectors: []*types.Selector{
				{Type: "S", Value: "1"},
			},
			FederatesWith:  []string{"domain1.com"},
			RevisionNumber: 1234,
		},
		// This entry should be ignored since it is missing an entry ID
		{
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			SpiffeId: &types.SPIFFEID{
				TrustDomain: "example.org",
				Path:        "/id2",
			},
			Selectors: []*types.Selector{
				{Type: "S", Value: "2"},
			},
			FederatesWith: []string{"domain2.com"},
		},
		// This entry should be ignored since it is missing a SPIFFE ID
		{
			Id:       "ENTRYID3",
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			Selectors: []*types.Selector{
				{Type: "S", Value: "3"},
			},
		},
		// This entry should be ignored since it is missing selectors
		{
			Id:       "ENTRYID4",
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			SpiffeId: &types.SPIFFEID{
				TrustDomain: "example.org",
				Path:        "/id4",
			},
		},
	}

	tc.svidClient.x509SVIDs = map[string]*types.X509SVID{
		"entry-id": {
			Id:        &types.SPIFFEID{TrustDomain: "example.org", Path: "/path"},
			CertChain: [][]byte{{11, 22, 33}},
		},
	}

	waitForRelease := make(chan struct{})
	tc.bundleClient.simulateRelease = func() {
		client.Release()
		close(waitForRelease)
	}

	tc.bundleClient.agentBundle = &types.Bundle{
		TrustDomain:     "example.org",
		X509Authorities: []*types.X509Certificate{{Asn1: []byte{10, 20, 30, 40}}},
	}
	tc.bundleClient.federatedBundles = map[string]*types.Bundle{
		"domain1.com": {
			TrustDomain:     "domain1.com",
			X509Authorities: []*types.X509Certificate{{Asn1: []byte{10, 20, 30, 40}}},
		},
		"domain2.com": {
			TrustDomain:     "domain2.com",
			X509Authorities: []*types.X509Certificate{{Asn1: []byte{10, 20, 30, 40}}},
		},
	}

	update, err := client.FetchUpdates(context.Background())
	require.NoError(t, err)

	assert.Equal(t, testBundles, update.Bundles)
	// Only the first registration entry should be returned since the rest are
	// invalid for one reason or another
	if assert.Len(t, update.Entries, 1) {
		entry := testEntries[0]
		assert.Equal(t, entry, update.Entries[entry.EntryId])
	}
	select {
	case <-waitForRelease:
	case <-time.After(time.Second * 5):
		require.FailNow(t, "timed out waiting for release")
	}
	assertConnectionIsNil(t, client)
}

func TestNewNodeClientRelease(t *testing.T) {
	client, _ := createClient()

	for i := 0; i < 3; i++ {
		// Create agent client and release
		_, r, err := client.newAgentClient(context.Background())
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)
		r.Release()

		// Create bundle client and release
		_, r, err = client.newBundleClient(context.Background())
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)
		r.Release()

		// Create entry client and release
		_, r, err = client.newEntryClient(context.Background())
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)
		r.Release()

		// Create svid client and release
		_, r, err = client.newSVIDClient(context.Background())
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)
		r.Release()

		// Release client
		client.Release()
		assertConnectionIsNil(t, client)
		// test that release is idempotent
		client.Release()
		assertConnectionIsNil(t, client)
	}
}

func TestNewNodeInternalClientRelease(t *testing.T) {
	client, _ := createClient()

	for i := 0; i < 3; i++ {
		// Create agent client
		_, conn, err := client.newAgentClient(context.Background())
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)

		client.release(conn)
		conn.Release()
		assertConnectionIsNil(t, client)

		// Create bundle client
		_, conn, err = client.newBundleClient(context.Background())
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)

		client.release(conn)
		conn.Release()
		assertConnectionIsNil(t, client)

		// Create entry client
		_, conn, err = client.newEntryClient(context.Background())
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)

		client.release(conn)
		conn.Release()
		assertConnectionIsNil(t, client)

		// Create svid client
		_, conn, err = client.newSVIDClient(context.Background())
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)

		client.release(conn)
		conn.Release()
		assertConnectionIsNil(t, client)
	}
}

func TestFetchUpdatesReleaseConnectionIfItFailsToFetch(t *testing.T) {
	for _, tt := range []struct {
		name      string
		err       string
		setupTest func(tc *testClient)
	}{
		{
			name: "Entries",
			setupTest: func(tc *testClient) {
				tc.entryClient.err = errors.New("an error")
			},
			err: "failed to fetch authorized entries: an error",
		},
		{
			name: "Agent bundle",
			setupTest: func(tc *testClient) {
				tc.bundleClient.bundleErr = errors.New("an error")
			},
			err: "failed to fetch bundle: an error",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			client, tc := createClient()
			tt.setupTest(tc)

			update, err := client.FetchUpdates(context.Background())
			assert.Nil(t, update)
			assert.EqualError(t, err, tt.err)
			assertConnectionIsNil(t, client)
		})
	}
}

func TestFetchUpdatesReleaseConnectionIfItFails(t *testing.T) {
	client, tc := createClient()

	tc.entryClient.err = errors.New("an error")

	update, err := client.FetchUpdates(context.Background())
	assert.Nil(t, update)
	assert.Error(t, err)
	assertConnectionIsNil(t, client)
}

func TestNewAgentClientFailsDial(t *testing.T) {
	client := newClient(&Config{
		KeysAndBundle: keysAndBundle,
		TrustDomain:   trustDomain,
	})
	agentClient, conn, err := client.newAgentClient(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to dial")
	require.Nil(t, agentClient)
	require.Nil(t, conn)
}

func TestNewBundleClientFailsDial(t *testing.T) {
	client := newClient(&Config{
		KeysAndBundle: keysAndBundle,
		TrustDomain:   trustDomain,
	})
	agentClient, conn, err := client.newBundleClient(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to dial")
	require.Nil(t, agentClient)
	require.Nil(t, conn)
}

func TestNewEntryClientFailsDial(t *testing.T) {
	client := newClient(&Config{
		KeysAndBundle: keysAndBundle,
		TrustDomain:   trustDomain,
	})
	agentClient, conn, err := client.newEntryClient(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to dial")
	require.Nil(t, agentClient)
	require.Nil(t, conn)
}

func TestNewSVIDClientFailsDial(t *testing.T) {
	client := newClient(&Config{
		KeysAndBundle: keysAndBundle,
		TrustDomain:   trustDomain,
	})
	agentClient, conn, err := client.newSVIDClient(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to dial")
	require.Nil(t, agentClient)
	require.Nil(t, conn)
}

func TestFetchJWTSVID(t *testing.T) {
	client, tc := createClient()
	ctx := context.Background()

	issuedAt := time.Now().Unix()
	expiresAt := time.Now().Add(time.Minute).Unix()
	for _, tt := range []struct {
		name       string
		setupTest  func(err error)
		err        string
		expectSVID *JWTSVID
		fetchErr   error
	}{
		{
			name: "success",
			setupTest: func(err error) {
				tc.svidClient.jwtSVID = &types.JWTSVID{
					Token:     "token",
					ExpiresAt: expiresAt,
					IssuedAt:  issuedAt,
				}
				tc.svidClient.newJWTSVID = err
			},
			expectSVID: &JWTSVID{
				Token:     "token",
				ExpiresAt: time.Unix(expiresAt, 0).UTC(),
				IssuedAt:  time.Unix(issuedAt, 0).UTC(),
			},
		},
		{
			name: "client fails",
			setupTest: func(err error) {
				tc.svidClient.newJWTSVID = err
			},
			err:      "failed to fetch JWT SVID: client fails",
			fetchErr: errors.New("client fails"),
		},
		{
			name: "empty response",
			setupTest: func(err error) {
				tc.svidClient.jwtSVID = nil
				tc.svidClient.newJWTSVID = err
			},
			err: "JWTSVID response missing SVID",
		},
		{
			name: "missing issuedAt",
			setupTest: func(err error) {
				tc.svidClient.jwtSVID = &types.JWTSVID{
					Token:     "token",
					ExpiresAt: expiresAt,
				}
				tc.svidClient.newJWTSVID = err
			},
			err: "JWTSVID missing issued at",
		},
		{
			name: "missing expiredAt",
			setupTest: func(err error) {
				tc.svidClient.jwtSVID = &types.JWTSVID{
					Token:    "token",
					IssuedAt: issuedAt,
				}
				tc.svidClient.newJWTSVID = err
			},
			err: "JWTSVID missing expires at",
		},
		{
			name: "issued after expired",
			setupTest: func(err error) {
				tc.svidClient.jwtSVID = &types.JWTSVID{
					Token:     "token",
					ExpiresAt: issuedAt,
					IssuedAt:  expiresAt,
				}
				tc.svidClient.newJWTSVID = err
			},
			err: "JWTSVID issued after it has expired",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			tt.setupTest(tt.fetchErr)
			resp, err := client.NewJWTSVID(ctx, "entry-id", []string{"myAud"})
			if tt.err != "" {
				require.Nil(t, resp)
				require.EqualError(t, err, tt.err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Equal(t, tt.expectSVID, resp)
		})
	}
}

// createClient creates a sample client with mocked components for testing purposes
func createClient() (*client, *testClient) {
	tc := &testClient{
		agentClient:  &fakeAgentClient{},
		bundleClient: &fakeBundleClient{},
		entryClient:  &fakeEntryClient{},
		svidClient:   &fakeSVIDClient{},
	}

	client := newClient(&Config{
		Addr:          "unix:///foo",
		Log:           log,
		KeysAndBundle: keysAndBundle,
		RotMtx:        new(sync.RWMutex),
		TrustDomain:   trustDomain,
	})
	client.createNewAgentClient = func(conn grpc.ClientConnInterface) agentv1.AgentClient {
		return tc.agentClient
	}
	client.createNewBundleClient = func(conn grpc.ClientConnInterface) bundlev1.BundleClient {
		return tc.bundleClient
	}
	client.createNewEntryClient = func(conn grpc.ClientConnInterface) entryv1.EntryClient {
		return tc.entryClient
	}
	client.createNewSVIDClient = func(conn grpc.ClientConnInterface) svidv1.SVIDClient {
		return tc.svidClient
	}

	client.dialContext = func(ctx context.Context, addr string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
		// make a normal grpc dial but without any of the provided options that may cause it to fail
		return grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	return client, tc
}

func keysAndBundle() ([]*x509.Certificate, crypto.Signer, []*x509.Certificate) {
	return nil, nil, nil
}

func assertConnectionIsNil(t *testing.T, client *client) {
	client.m.Lock()
	assert.Nil(t, client.connections, "Connection should be released")
	client.m.Unlock()
}

func assertConnectionIsNotNil(t *testing.T, client *client) {
	client.m.Lock()
	assert.NotNil(t, client.connections, "Connection should not be released")
	client.m.Unlock()
}

type fakeEntryClient struct {
	entryv1.EntryClient
	entries []*types.Entry
	err     error
}

func (c *fakeEntryClient) GetAuthorizedEntries(ctx context.Context, in *entryv1.GetAuthorizedEntriesRequest, opts ...grpc.CallOption) (*entryv1.GetAuthorizedEntriesResponse, error) {
	if c.err != nil {
		return nil, c.err
	}
	if diff := cmp.Diff(in.OutputMask, &types.EntryMask{
		SpiffeId:       true,
		Selectors:      true,
		FederatesWith:  true,
		Admin:          true,
		Downstream:     true,
		RevisionNumber: true,
		StoreSvid:      true,
	}, protocmp.Transform()); diff != "" {
		return nil, status.Error(codes.InvalidArgument, "invalid output mask requested")
	}

	return &entryv1.GetAuthorizedEntriesResponse{
		Entries: c.entries,
	}, nil
}

type fakeBundleClient struct {
	bundlev1.BundleClient

	agentBundle        *types.Bundle
	federatedBundles   map[string]*types.Bundle
	bundleErr          error
	federatedBundleErr error

	simulateRelease func()
}

func (c *fakeBundleClient) GetBundle(ctx context.Context, in *bundlev1.GetBundleRequest, opts ...grpc.CallOption) (*types.Bundle, error) {
	if c.bundleErr != nil {
		return nil, c.bundleErr
	}

	if c.simulateRelease != nil {
		go c.simulateRelease()
	}

	return c.agentBundle, nil
}

func (c *fakeBundleClient) GetFederatedBundle(ctx context.Context, in *bundlev1.GetFederatedBundleRequest, opts ...grpc.CallOption) (*types.Bundle, error) {
	if c.federatedBundleErr != nil {
		return nil, c.federatedBundleErr
	}
	b, ok := c.federatedBundles[in.TrustDomain]
	if !ok {
		return nil, errors.New("no federated bundle found")
	}

	return b, nil
}

type fakeSVIDClient struct {
	svidv1.SVIDClient
	batchSVIDErr    error
	newJWTSVID      error
	x509SVIDs       map[string]*types.X509SVID
	jwtSVID         *types.JWTSVID
	simulateRelease func()
}

func (c *fakeSVIDClient) BatchNewX509SVID(ctx context.Context, in *svidv1.BatchNewX509SVIDRequest, opts ...grpc.CallOption) (*svidv1.BatchNewX509SVIDResponse, error) {
	if c.batchSVIDErr != nil {
		return nil, c.batchSVIDErr
	}

	// Simulate async calls
	if c.simulateRelease != nil {
		go c.simulateRelease()
	}

	var results []*svidv1.BatchNewX509SVIDResponse_Result
	for _, param := range in.Params {
		svid, ok := c.x509SVIDs[param.EntryId]
		switch {
		case ok:
			results = append(results, &svidv1.BatchNewX509SVIDResponse_Result{
				Status: &types.Status{
					Code: int32(codes.OK),
				},
				Svid: svid,
			})
		default:
			results = append(results, &svidv1.BatchNewX509SVIDResponse_Result{
				Status: &types.Status{
					Code:    int32(codes.NotFound),
					Message: "svid not found",
				},
			})
		}
	}

	return &svidv1.BatchNewX509SVIDResponse{
		Results: results,
	}, nil
}

func (c *fakeSVIDClient) NewJWTSVID(ctx context.Context, in *svidv1.NewJWTSVIDRequest, opts ...grpc.CallOption) (*svidv1.NewJWTSVIDResponse, error) {
	if c.newJWTSVID != nil {
		return nil, c.newJWTSVID
	}
	return &svidv1.NewJWTSVIDResponse{
		Svid: c.jwtSVID,
	}, nil
}

type fakeAgentClient struct {
	agentv1.AgentClient
	err  error
	svid *types.X509SVID
}

func (c *fakeAgentClient) RenewAgent(ctx context.Context, in *agentv1.RenewAgentRequest, opts ...grpc.CallOption) (*agentv1.RenewAgentResponse, error) {
	if c.err != nil {
		return nil, c.err
	}

	if in.Params == nil || len(in.Params.Csr) == 0 {
		return nil, errors.New("malformed param")
	}

	return &agentv1.RenewAgentResponse{
		Svid: c.svid,
	}, nil
}

type testClient struct {
	agentClient  *fakeAgentClient
	bundleClient *fakeBundleClient
	entryClient  *fakeEntryClient
	svidClient   *fakeSVIDClient
}
