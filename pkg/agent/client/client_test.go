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

	req := &node.FetchX509SVIDRequest{
		Csrs: [][]byte{{1, 2, 3, 4}},
	}
	res := &node.FetchX509SVIDResponse{
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
	assert.NotNil(t, client.conn)
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
	assert.Nil(t, client.conn, "Connection was not released")
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
	assert.Nil(t, client.conn, "Connection was not released")
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
	assert.Nil(t, client.conn, "Connection was not released")
}

// Creates a sample client with mocked components for testing purposes
func createClient(t *testing.T, nodeClient *mock_node.MockNodeClient) *client {
	cfg := &Config{
		Log:           log,
		KeysAndBundle: keysAndBundle,
	}
	client := New(cfg)
	client.newNodeClientCallback = func() (node.NodeClient, error) {
		return nodeClient, nil
	}

	// Simulate a not nil connection
	conn, err := client.dial(context.Background())
	if err != nil {
		assert.Fail(t, "Could not create connection")
	}
	client.conn = conn

	return client
}

func keysAndBundle() ([]*x509.Certificate, *ecdsa.PrivateKey, []*x509.Certificate) {
	return nil, nil, nil
}
