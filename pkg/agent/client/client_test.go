package client

import (
	"context"
	"io"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/mock/proto/api/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	log, _ = test.NewNullLogger()
)

func TestFetchUpdates(t *testing.T) {
	cfg := &Config{
		Log: log,
	}

	ctrl := gomock.NewController(t)
	nodeClient := mock_node.NewMockNodeClient(ctrl)
	nodeFsc := mock_node.NewMockNode_FetchX509SVIDClient(ctrl)

	client := New(cfg)
	client.newNodeClientCallback = func() (node.NodeClient, error) {
		return nodeClient, nil
	}
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
					DEPRECATEDCert: []byte{11, 22, 33},
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
	client.Release()
}
