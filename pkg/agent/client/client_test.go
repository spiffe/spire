package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"io"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/proto/spire/api/node"
	"github.com/spiffe/spire/proto/spire/common"
	mock_node "github.com/spiffe/spire/test/mock/proto/api/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

var (
	log, _ = test.NewNullLogger()
)

func TestFetchUpdates(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	nodeClient := mock_node.NewMockNodeClient(ctrl)
	nodeFsc := mock_node.NewMockNode_FetchX509SVIDClient(ctrl)
	client := createClient(t, nodeClient)

	req := newTestFetchX509SVIDRequest()
	res := newTestFetchX509SVIDResponse()

	nodeClient.EXPECT().FetchX509SVID(gomock.Any()).Return(nodeFsc, nil)
	nodeFsc.EXPECT().Send(req)
	nodeFsc.EXPECT().CloseSend()
	nodeFsc.EXPECT().Recv().Return(res, nil)
	nodeFsc.EXPECT().Recv().Return(nil, io.EOF)

	update, err := client.FetchUpdates(context.Background(), req)
	require.Nil(t, err)

	assert.Equal(t, res.SvidUpdate.Bundles, update.Bundles)
	assert.Equal(t, res.SvidUpdate.Svids, update.SVIDs)
	for _, entry := range res.SvidUpdate.RegistrationEntries {
		assert.Equal(t, entry, update.Entries[entry.EntryId])
	}
	assertNodeConnIsNotNil(t, client)
}

func newTestFetchX509SVIDRequest() *node.FetchX509SVIDRequest {
	return &node.FetchX509SVIDRequest{
		Csrs: map[string][]byte{
			"entry-id": []byte{1, 2, 3, 4}},
	}
}

func newTestFetchX509SVIDResponse() *node.FetchX509SVIDResponse {
	return &node.FetchX509SVIDResponse{
		SvidUpdate: &node.X509SVIDUpdate{
			RegistrationEntries: []*common.RegistrationEntry{{
				EntryId: "1",
			}},
			Svids: map[string]*node.X509SVID{
				"someSpiffeId": {
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
			},
		},
	}
}

func TestFetchReleaseWaitsForFetchUpdatesToFinish(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	nodeClient := mock_node.NewMockNodeClient(ctrl)
	nodeFsc := mock_node.NewMockNode_FetchX509SVIDClient(ctrl)
	client := createClient(t, nodeClient)

	req := newTestFetchX509SVIDRequest()
	res := newTestFetchX509SVIDResponse()

	waitForRelease := make(chan struct{})
	releaseClientMidRequest := func() {
		client.Release()
		close(waitForRelease)
	}

	nodeClient.EXPECT().FetchX509SVID(gomock.Any()).Return(nodeFsc, nil)
	nodeFsc.EXPECT().Send(req).Do(func(interface{}) {
		// simulate an uncoorindated call to Release mid-Fetch
		go releaseClientMidRequest()
	})
	nodeFsc.EXPECT().CloseSend()
	nodeFsc.EXPECT().Recv().Return(res, nil)
	nodeFsc.EXPECT().Recv().Return(nil, io.EOF)

	update, err := client.FetchUpdates(context.Background(), req)
	require.Nil(t, err)

	assert.Equal(t, res.SvidUpdate.Bundles, update.Bundles)
	assert.Equal(t, res.SvidUpdate.Svids, update.SVIDs)
	for _, entry := range res.SvidUpdate.RegistrationEntries {
		assert.Equal(t, entry, update.Entries[entry.EntryId])
	}
	<-waitForRelease
	assertNodeConnIsNil(t, client)
}

func TestNewNodeClientRelease(t *testing.T) {
	client := createClient(t, nil)

	for i := 0; i < 3; i++ {
		_, r, err := client.newNodeClient(context.Background())
		require.NoError(t, err)
		assertNodeConnIsNotNil(t, client)

		r.Release()
		client.Release()
		assertNodeConnIsNil(t, client)
		// test that release is idempotent
		client.Release()
		assertNodeConnIsNil(t, client)
	}
}

func TestNewNodeInternalClientRelease(t *testing.T) {
	client := createClient(t, nil)

	for i := 0; i < 3; i++ {
		_, nodeConn, err := client.newNodeClient(context.Background())
		require.NoError(t, err)
		assertNodeConnIsNotNil(t, client)

		client.release(nodeConn)
		nodeConn.Release()
		assertNodeConnIsNil(t, client)
	}
}

func TestFetchUpdatesReleaseConnectionIfItFailsToFetchX509SVID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	nodeClient := mock_node.NewMockNodeClient(ctrl)
	nodeClient.EXPECT().FetchX509SVID(gomock.Any()).Return(nil, errors.New("an error"))
	client := createClient(t, nodeClient)

	update, err := client.FetchUpdates(context.Background(), &node.FetchX509SVIDRequest{})
	assert.Nil(t, update)
	assert.Error(t, err)
	assertNodeConnIsNil(t, client)
}

func TestFetchUpdatesReleaseConnectionIfItFailsToSendRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	nodeClient := mock_node.NewMockNodeClient(ctrl)
	nodeFsc := mock_node.NewMockNode_FetchX509SVIDClient(ctrl)
	req := &node.FetchX509SVIDRequest{}
	nodeFsc.EXPECT().Send(req).Return(errors.New("an error"))
	nodeFsc.EXPECT().CloseSend()
	nodeClient.EXPECT().FetchX509SVID(gomock.Any()).Return(nodeFsc, nil)
	client := createClient(t, nodeClient)

	update, err := client.FetchUpdates(context.Background(), req)
	assert.Nil(t, update)
	assert.Error(t, err)
	assertNodeConnIsNil(t, client)
}

func TestFetchUpdatesReleaseConnectionIfItFailsToReceiveResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	nodeClient := mock_node.NewMockNodeClient(ctrl)
	nodeFsc := mock_node.NewMockNode_FetchX509SVIDClient(ctrl)
	req := &node.FetchX509SVIDRequest{}
	nodeFsc.EXPECT().Send(req).Return(nil)
	nodeFsc.EXPECT().CloseSend()
	nodeFsc.EXPECT().Recv().Return(nil, errors.New("an error"))
	nodeClient.EXPECT().FetchX509SVID(gomock.Any()).Return(nodeFsc, nil)
	client := createClient(t, nodeClient)

	update, err := client.FetchUpdates(context.Background(), req)
	assert.Nil(t, update)
	assert.Error(t, err)
	assertNodeConnIsNil(t, client)
}

// Creates a sample client with mocked components for testing purposes
func createClient(t *testing.T, nodeClient *mock_node.MockNodeClient) *client {
	client := New(&Config{
		Log:           log,
		KeysAndBundle: keysAndBundle,
	})
	client.createNewNodeClient = func(conn *grpc.ClientConn) node.NodeClient {
		return nodeClient
	}
	return client
}

func keysAndBundle() ([]*x509.Certificate, *ecdsa.PrivateKey, []*x509.Certificate) {
	return nil, nil, nil
}

func assertNodeConnIsNil(t *testing.T, client *client) {
	client.m.Lock()
	assert.Nil(t, client.nodeConn, "Connection should be released")
	client.m.Unlock()
}

func assertNodeConnIsNotNil(t *testing.T, client *client) {
	client.m.Lock()
	assert.NotNil(t, client.nodeConn, "Connection should not be released")
	client.m.Unlock()
}
