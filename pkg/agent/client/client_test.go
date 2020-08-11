package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/proto/spire/api/node"
	agentpb "github.com/spiffe/spire/proto/spire/api/server/agent/v1"
	bundlepb "github.com/spiffe/spire/proto/spire/api/server/bundle/v1"
	entrypb "github.com/spiffe/spire/proto/spire/api/server/entry/v1"
	svidpb "github.com/spiffe/spire/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/types"
	mock_node "github.com/spiffe/spire/test/mock/proto/api/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

var (
	log, _ = test.NewNullLogger()

	trustDomainURL = url.URL{Scheme: "spiffe", Host: "example.org"}
)

func TestFetchUpdates(t *testing.T) {
	client, tc := createClient(t)
	defer tc.Release()

	req := newTestFetchX509SVIDRequest()
	res := newTestFetchX509SVIDResponse()

	for _, tt := range []struct {
		enableExperimental bool
		setupExpect        func()
	}{
		{
			enableExperimental: false,
			setupExpect: func() {
				nodeFsc := mock_node.NewMockNode_FetchX509SVIDClient(tc.ctrl)
				tc.nodeClient.EXPECT().FetchX509SVID(gomock.Any()).Return(nodeFsc, nil)
				nodeFsc.EXPECT().Send(req)
				nodeFsc.EXPECT().CloseSend()
				nodeFsc.EXPECT().Recv().Return(res, nil)
				nodeFsc.EXPECT().Recv().Return(nil, io.EOF)
			},
		},
		{
			enableExperimental: true,
			setupExpect: func() {
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
					TrustDomain:     "spiffe://example.org",
					X509Authorities: []*types.X509Certificate{{Asn1: []byte{10, 20, 30, 40}}},
				}
				tc.bundleClient.federatedBundles = map[string]*types.Bundle{
					"spiffe://domain1.com": {
						TrustDomain:     "spiffe://domain1.com",
						X509Authorities: []*types.X509Certificate{{Asn1: []byte{10, 20, 30, 40}}},
					},
					"spiffe://domain2.com": {
						TrustDomain:     "spiffe://domain2.com",
						X509Authorities: []*types.X509Certificate{{Asn1: []byte{10, 20, 30, 40}}},
					},
				}
			},
		},
	} {
		tt := tt
		name := fmt.Sprintf("experimental %v", tt.enableExperimental)
		t.Run(name, func(t *testing.T) {
			client.c.ExperimentalAPIEnabled = tt.enableExperimental
			tt.setupExpect()

			// Simulate an ongoing SVID rotation (request should not be made in the middle of a rotation)
			client.c.RotMtx.Lock()

			// Do the request in a different go routine
			var wg sync.WaitGroup
			var update *Update
			err := errors.New("a not nil error")
			wg.Add(1)
			go func() {
				defer wg.Done()
				update, err = client.FetchUpdates(context.Background(), req, false)
			}()

			// The request should wait until the SVID rotation finishes
			require.Contains(t, "a not nil error", err.Error())
			require.Nil(t, update)

			// Simulate the end of the SVID rotation
			client.c.RotMtx.Unlock()
			wg.Wait()

			// Assert results
			require.Nil(t, err)
			assert.Equal(t, res.SvidUpdate.Bundles, update.Bundles)
			assert.Equal(t, res.SvidUpdate.Svids, update.SVIDs)
			// Only the first registration entry should be returned since the rest are
			// invalid for one reason or another
			if assert.Len(t, update.Entries, 1) {
				entry := res.SvidUpdate.RegistrationEntries[0]
				assert.Equal(t, entry, update.Entries[entry.EntryId])
			}
			assertConnectionIsNotNil(t, client)
		})
	}
}

func TestFetchUpdatesForRotation(t *testing.T) {
	client, tc := createClient(t)
	defer tc.Release()

	for _, tt := range []struct {
		name       string
		agentErr   error
		err        string
		expectSVID map[string]*node.X509SVID
		req        *node.FetchX509SVIDRequest
		agentSVID  *types.X509SVID
	}{
		{
			name: "success",
			req: &node.FetchX509SVIDRequest{
				Csrs: map[string][]byte{
					"spiffe://example.org/agent1": {0, 1, 2},
				},
			},
			agentSVID: &types.X509SVID{
				Id: &types.SPIFFEID{
					TrustDomain: "example.org",
					Path:        "/agent1",
				},
				CertChain: [][]byte{{1, 2, 3}},
				ExpiresAt: 12345,
			},
			expectSVID: map[string]*node.X509SVID{
				"spiffe://example.org/agent1": {
					CertChain: []byte{1, 2, 3},
					ExpiresAt: 12345,
				},
			},
		},
		{
			name: "no csr",
			req: &node.FetchX509SVIDRequest{
				Csrs: map[string][]byte{},
			},
			agentSVID: &types.X509SVID{
				Id: &types.SPIFFEID{
					TrustDomain: "example.org",
					Path:        "/agent1",
				},
				CertChain: [][]byte{{1, 2, 3}},
				ExpiresAt: 12345,
			},
			expectSVID: map[string]*node.X509SVID{},
		},
		{
			name: "renew agent fails",
			req: &node.FetchX509SVIDRequest{
				Csrs: map[string][]byte{
					"spiffe://example.org/agent1": {0, 1, 2},
				},
			},
			agentErr: errors.New("renew fails"),
			err:      "renew fails",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			client.c.ExperimentalAPIEnabled = true
			tc.agentClient.err = tt.agentErr
			tc.agentClient.svid = tt.agentSVID

			resp, err := client.FetchUpdates(context.Background(), tt.req, true)
			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				require.Nil(t, resp)
				return
			}

			require.Nil(t, err)
			require.Equal(t, resp, &Update{SVIDs: tt.expectSVID})

			assertConnectionIsNotNil(t, client)
		})
	}
}
func newTestFetchX509SVIDRequest() *node.FetchX509SVIDRequest {
	return &node.FetchX509SVIDRequest{
		Csrs: map[string][]byte{
			"entry-id": {1, 2, 3, 4}},
	}
}

func newTestFetchX509SVIDResponse() *node.FetchX509SVIDResponse {
	return &node.FetchX509SVIDResponse{
		SvidUpdate: &node.X509SVIDUpdate{
			RegistrationEntries: []*common.RegistrationEntry{
				{
					EntryId:  "ENTRYID1",
					ParentId: "spiffe://example.org/host",
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
					ParentId: "spiffe://example.org/host",
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
					EntryId:  "ENTRYID3",
					ParentId: "spiffe://example.org/host",
					Selectors: []*common.Selector{
						{Type: "S", Value: "3"},
					},
				},
				// This entry should be ignored since it is missing selectors
				{
					EntryId:  "ENTRYID4",
					ParentId: "spiffe://example.org/host",
					SpiffeId: "spiffe://example.org/id4",
				},
			},
			Svids: map[string]*node.X509SVID{
				"entry-id": {
					CertChain: []byte{11, 22, 33},
				},
			},
			Bundles: map[string]*common.Bundle{
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
			},
		},
	}
}

func TestFetchReleaseWaitsForFetchUpdatesToFinish(t *testing.T) {
	client, tc := createClient(t)
	defer tc.Release()

	nodeFsc := mock_node.NewMockNode_FetchX509SVIDClient(tc.ctrl)

	req := newTestFetchX509SVIDRequest()
	res := newTestFetchX509SVIDResponse()

	for _, tt := range []struct {
		enableExperimental bool
		setupExpect        func(release func())
	}{
		{
			enableExperimental: false,
			setupExpect: func(release func()) {
				tc.nodeClient.EXPECT().FetchX509SVID(gomock.Any()).Return(nodeFsc, nil)
				nodeFsc.EXPECT().Send(req).Do(func(interface{}) {
					// simulate an uncoorindated call to Release mid-Fetch
					go release()
				})
				nodeFsc.EXPECT().CloseSend()
				nodeFsc.EXPECT().Recv().Return(res, nil)
				nodeFsc.EXPECT().Recv().Return(nil, io.EOF)
			},
		},
		{
			enableExperimental: true,
			setupExpect: func(release func()) {
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

				tc.svidClient.simulateRelease = release
				tc.bundleClient.agentBundle = &types.Bundle{
					TrustDomain:     "spiffe://example.org",
					X509Authorities: []*types.X509Certificate{{Asn1: []byte{10, 20, 30, 40}}},
				}
				tc.bundleClient.federatedBundles = map[string]*types.Bundle{
					"spiffe://domain1.com": {
						TrustDomain:     "spiffe://domain1.com",
						X509Authorities: []*types.X509Certificate{{Asn1: []byte{10, 20, 30, 40}}},
					},
					"spiffe://domain2.com": {
						TrustDomain:     "spiffe://domain2.com",
						X509Authorities: []*types.X509Certificate{{Asn1: []byte{10, 20, 30, 40}}},
					},
				}
			},
		},
	} {
		tt := tt
		name := fmt.Sprintf("experimental %v", tt.enableExperimental)
		t.Run(name, func(t *testing.T) {
			waitForRelease := make(chan struct{})
			releaseClientMidRequest := func() {
				client.Release()
				close(waitForRelease)
			}
			client.c.ExperimentalAPIEnabled = tt.enableExperimental
			tt.setupExpect(releaseClientMidRequest)

			update, err := client.FetchUpdates(context.Background(), req, false)
			require.Nil(t, err)

			assert.Equal(t, res.SvidUpdate.Bundles, update.Bundles)
			assert.Equal(t, res.SvidUpdate.Svids, update.SVIDs)
			// Only the first registration entry should be returned since the rest are
			// invalid for one reason or another
			if assert.Len(t, update.Entries, 1) {
				entry := res.SvidUpdate.RegistrationEntries[0]
				assert.Equal(t, entry, update.Entries[entry.EntryId])
			}
			<-waitForRelease
			assertConnectionIsNil(t, client)
		})
	}
}

func TestNewNodeClientRelease(t *testing.T) {
	client, tc := createClient(t)
	defer tc.Release()

	for i := 0; i < 3; i++ {
		// Create node client and release
		_, r, err := client.newNodeClient(context.Background())
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)
		r.Release()

		// Create agent client and release
		_, r, err = client.newAgentClient(context.Background())
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
	client, tc := createClient(t)
	defer tc.Release()

	for i := 0; i < 3; i++ {
		// Create node client
		_, conn, err := client.newNodeClient(context.Background())
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)

		client.release(conn)
		conn.Release()
		assertConnectionIsNil(t, client)

		// Create agent client
		_, conn, err = client.newAgentClient(context.Background())
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
		name         string
		experimental bool
		err          string
		setupTest    func(tc *testClient)
	}{
		{
			name: "X509SVID",
			setupTest: func(tc *testClient) {
				tc.nodeClient.EXPECT().FetchX509SVID(gomock.Any()).Return(nil, errors.New("an error"))
			},
			err: "unable to get a stream",
		},
		{
			name:         "Entries",
			experimental: true,
			setupTest: func(tc *testClient) {
				tc.entryClient.err = errors.New("an error")
			},
			err: "failed to fetch authorized entries",
		},
		{
			name:         "Agent bundle",
			experimental: true,
			setupTest: func(tc *testClient) {
				tc.bundleClient.bundleErr = errors.New("an error")
			},
			err: "failed to fetch bundle",
		},
		{
			name:         "SVID",
			experimental: true,
			setupTest: func(tc *testClient) {
				tc.bundleClient.agentBundle = &types.Bundle{
					TrustDomain:     "spiffe://example.org",
					X509Authorities: []*types.X509Certificate{{Asn1: []byte{10, 20, 30, 40}}},
				}
				tc.svidClient.batchSVIDErr = errors.New("an error")
			},
			err: "failed to batch new X509 SVID(s)",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			client, tc := createClient(t)
			defer tc.Release()
			tt.setupTest(tc)
			client.c.ExperimentalAPIEnabled = tt.experimental

			update, err := client.FetchUpdates(context.Background(), &node.FetchX509SVIDRequest{
				Csrs: map[string][]byte{
					"entry-id": {1, 2},
				},
			}, false)
			assert.Nil(t, update)
			assert.EqualError(t, err, tt.err)
			assertConnectionIsNil(t, client)
		})
	}
}

func TestFetchUpdatesReleaseConnectionIfItFailsToSendRequest(t *testing.T) {
	client, tc := createClient(t)
	defer tc.Release()

	nodeFsc := mock_node.NewMockNode_FetchX509SVIDClient(tc.ctrl)
	req := &node.FetchX509SVIDRequest{}
	nodeFsc.EXPECT().Send(req).Return(errors.New("an error"))
	tc.nodeClient.EXPECT().FetchX509SVID(gomock.Any()).Return(nodeFsc, nil)

	update, err := client.FetchUpdates(context.Background(), req, false)
	assert.Nil(t, update)
	assert.Error(t, err)
	assertConnectionIsNil(t, client)
}

func TestFetchUpdatesReleaseConnectionIfItFailsToReceiveResponse(t *testing.T) {
	client, tc := createClient(t)
	defer tc.Release()

	nodeFsc := mock_node.NewMockNode_FetchX509SVIDClient(tc.ctrl)
	req := &node.FetchX509SVIDRequest{}
	nodeFsc.EXPECT().Send(req).Return(nil)
	nodeFsc.EXPECT().CloseSend().Return(nil)
	nodeFsc.EXPECT().Recv().Return(nil, errors.New("an error"))
	tc.nodeClient.EXPECT().FetchX509SVID(gomock.Any()).Return(nodeFsc, nil)

	update, err := client.FetchUpdates(context.Background(), req, false)
	assert.Nil(t, update)
	assert.Error(t, err)
	assertConnectionIsNil(t, client)
}

func TestNewClientFailsDial(t *testing.T) {
	client := newClient(&Config{
		KeysAndBundle: keysAndBundle,
		TrustDomain:   trustDomainURL,
	})
	nodeClient, nodeConn, err := client.newNodeClient(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "dial tcp: missing address")
	require.Nil(t, nodeClient)
	require.Nil(t, nodeConn)
}

func TestNewAgentClientFailsDial(t *testing.T) {
	client := newClient(&Config{
		KeysAndBundle: keysAndBundle,
		TrustDomain:   trustDomainURL,
	})
	agentClient, conn, err := client.newAgentClient(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "dial tcp: missing address")
	require.Nil(t, agentClient)
	require.Nil(t, conn)
}

func TestNewBundleClientFailsDial(t *testing.T) {
	client := newClient(&Config{
		KeysAndBundle: keysAndBundle,
		TrustDomain:   trustDomainURL,
	})
	agentClient, conn, err := client.newBundleClient(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "dial tcp: missing address")
	require.Nil(t, agentClient)
	require.Nil(t, conn)
}

func TestNewEntryClientFailsDial(t *testing.T) {
	client := newClient(&Config{
		KeysAndBundle: keysAndBundle,
		TrustDomain:   trustDomainURL,
	})
	agentClient, conn, err := client.newEntryClient(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "dial tcp: missing address")
	require.Nil(t, agentClient)
	require.Nil(t, conn)
}

func TestNewSVIDClientFailsDial(t *testing.T) {
	client := newClient(&Config{
		KeysAndBundle: keysAndBundle,
		TrustDomain:   trustDomainURL,
	})
	agentClient, conn, err := client.newSVIDClient(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "dial tcp: missing address")
	require.Nil(t, agentClient)
	require.Nil(t, conn)
}

func TestFetchJWTSVID(t *testing.T) {
	client, tc := createClient(t)
	defer tc.Release()
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
				tc.nodeClient.EXPECT().FetchJWTSVID(gomock.Any(), gomock.Any()).Return(&node.FetchJWTSVIDResponse{
					Svid: &node.JWTSVID{
						Token:     "token",
						ExpiresAt: expiresAt,
						IssuedAt:  issuedAt,
					},
				}, nil)
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
				tc.nodeClient.EXPECT().FetchJWTSVID(gomock.Any(), gomock.Any()).Return(nil, err)
			},
			err:      "unable to get a stream",
			fetchErr: errors.New("client fails"),
		},
		{
			name: "empty response",
			setupTest: func(err error) {
				tc.nodeClient.EXPECT().FetchJWTSVID(gomock.Any(), gomock.Any()).Return(&node.FetchJWTSVIDResponse{}, nil)
			},
			err: "JWTSVID response missing SVID",
		},
		{
			name: "missing issuedAt",
			setupTest: func(err error) {
				tc.nodeClient.EXPECT().FetchJWTSVID(gomock.Any(), gomock.Any()).Return(&node.FetchJWTSVIDResponse{
					Svid: &node.JWTSVID{
						Token:     "token",
						ExpiresAt: expiresAt,
					},
				}, nil)
			},
			err: "JWTSVID missing issued at",
		},
		{
			name: "missing expiredAt",
			setupTest: func(err error) {
				tc.nodeClient.EXPECT().FetchJWTSVID(gomock.Any(), gomock.Any()).Return(&node.FetchJWTSVIDResponse{
					Svid: &node.JWTSVID{
						Token:    "token",
						IssuedAt: issuedAt,
					},
				}, nil)
			},
			err: "JWTSVID missing expires at",
		},
		{
			name: "issued after expired",
			setupTest: func(err error) {
				tc.nodeClient.EXPECT().FetchJWTSVID(gomock.Any(), gomock.Any()).Return(&node.FetchJWTSVIDResponse{
					Svid: &node.JWTSVID{
						Token:     "token",
						ExpiresAt: issuedAt,
						IssuedAt:  expiresAt,
					},
				}, nil)
			},
			err: "JWTSVID issued after it has expired",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			tt.setupTest(tt.fetchErr)
			resp, err := client.FetchJWTSVID(ctx, &node.JSR{
				SpiffeId: "spiffe://example.org/host",
				Audience: []string{"myAud"},
			}, "entry-id")
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

func TestFetchJWTSVIDExperimental(t *testing.T) {
	client, tc := createClient(t)
	defer tc.Release()
	ctx := context.Background()
	client.c.ExperimentalAPIEnabled = true

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
			err:      "failure fetching JWT SVID: client fails",
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
			resp, err := client.FetchJWTSVID(ctx, &node.JSR{
				SpiffeId: "spiffe://example.org/host",
				Audience: []string{"myAud"},
			}, "entry-id")
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
func createClient(tb testing.TB) (*client, *testClient) {
	ctrl := gomock.NewController(tb)
	tc := &testClient{
		ctrl:         ctrl,
		nodeClient:   mock_node.NewMockNodeClient(ctrl),
		agentClient:  &fakeAgentClient{},
		bundleClient: &fakeBundleClient{},
		entryClient:  &fakeEntryClient{},
		svidClient:   &fakeSVIDClient{},
	}

	client := newClient(&Config{
		Log:           log,
		KeysAndBundle: keysAndBundle,
		RotMtx:        new(sync.RWMutex),
		TrustDomain:   trustDomainURL,
	})
	client.createNewNodeClient = func(conn grpc.ClientConnInterface) node.NodeClient {
		return tc.nodeClient
	}
	client.createNewAgentClient = func(conn grpc.ClientConnInterface) agentpb.AgentClient {
		return tc.agentClient
	}

	client.createNewBundleClient = func(conn grpc.ClientConnInterface) bundlepb.BundleClient {
		return tc.bundleClient
	}
	client.createNewEntryClient = func(conn grpc.ClientConnInterface) entrypb.EntryClient {
		return tc.entryClient
	}
	client.createNewSVIDClient = func(conn grpc.ClientConnInterface) svidpb.SVIDClient {
		return tc.svidClient
	}

	client.dialContext = func(ctx context.Context, addr string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
		// make a normal grpc dial but without any of the provided options that may cause it to fail
		return grpc.DialContext(ctx, addr, grpc.WithInsecure())
	}
	return client, tc
}

func keysAndBundle() ([]*x509.Certificate, *ecdsa.PrivateKey, []*x509.Certificate) {
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
	entrypb.EntryClient
	entries []*types.Entry
	err     error
}

func (c *fakeEntryClient) GetAuthorizedEntries(ctx context.Context, in *entrypb.GetAuthorizedEntriesRequest, opts ...grpc.CallOption) (*entrypb.GetAuthorizedEntriesResponse, error) {
	if c.err != nil {
		return nil, c.err
	}
	return &entrypb.GetAuthorizedEntriesResponse{
		Entries: c.entries,
	}, nil
}

type fakeBundleClient struct {
	bundlepb.BundleClient

	agentBundle        *types.Bundle
	federatedBundles   map[string]*types.Bundle
	bundleErr          error
	federatedBundleErr error
}

func (c *fakeBundleClient) GetBundle(ctx context.Context, in *bundlepb.GetBundleRequest, opts ...grpc.CallOption) (*types.Bundle, error) {
	if c.bundleErr != nil {
		return nil, c.bundleErr
	}

	return c.agentBundle, nil
}

func (c *fakeBundleClient) GetFederatedBundle(ctx context.Context, in *bundlepb.GetFederatedBundleRequest, opts ...grpc.CallOption) (*types.Bundle, error) {
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
	svidpb.SVIDClient
	batchSVIDErr    error
	newJWTSVID      error
	x509SVIDs       map[string]*types.X509SVID
	jwtSVID         *types.JWTSVID
	simulateRelease func()
}

func (c *fakeSVIDClient) BatchNewX509SVID(ctx context.Context, in *svidpb.BatchNewX509SVIDRequest, opts ...grpc.CallOption) (*svidpb.BatchNewX509SVIDResponse, error) {
	if c.batchSVIDErr != nil {
		return nil, c.batchSVIDErr
	}

	// Simulate async calls
	if c.simulateRelease != nil {
		go c.simulateRelease()
	}

	var results []*svidpb.BatchNewX509SVIDResponse_Result
	for _, param := range in.Params {
		svid, ok := c.x509SVIDs[param.EntryId]
		switch {
		case ok:
			results = append(results, &svidpb.BatchNewX509SVIDResponse_Result{
				Status: &types.Status{
					Code: int32(codes.OK),
				},
				Svid: svid,
			})
		default:
			results = append(results, &svidpb.BatchNewX509SVIDResponse_Result{
				Status: &types.Status{
					Code:    int32(codes.NotFound),
					Message: "svid not found",
				},
			})
		}
	}

	return &svidpb.BatchNewX509SVIDResponse{
		Results: results,
	}, nil
}

func (c *fakeSVIDClient) NewJWTSVID(ctx context.Context, in *svidpb.NewJWTSVIDRequest, opts ...grpc.CallOption) (*svidpb.NewJWTSVIDResponse, error) {
	if c.newJWTSVID != nil {
		return nil, c.newJWTSVID
	}
	return &svidpb.NewJWTSVIDResponse{
		Svid: c.jwtSVID,
	}, nil
}

type fakeAgentClient struct {
	agentpb.AgentClient
	err  error
	svid *types.X509SVID
}

func (c *fakeAgentClient) RenewAgent(ctx context.Context, in *agentpb.RenewAgentRequest, opts ...grpc.CallOption) (*agentpb.RenewAgentResponse, error) {
	if c.err != nil {
		return nil, c.err
	}

	if in.Params == nil || len(in.Params.Csr) == 0 {
		return nil, errors.New("malformed param")
	}

	return &agentpb.RenewAgentResponse{
		Svid: c.svid,
	}, nil
}

type testClient struct {
	nodeClient   *mock_node.MockNodeClient
	ctrl         *gomock.Controller
	agentClient  *fakeAgentClient
	bundleClient *fakeBundleClient
	entryClient  *fakeEntryClient
	svidClient   *fakeSVIDClient
}

func (c *testClient) Release() {
	c.ctrl.Finish()
}
