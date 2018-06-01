package client

import (
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
	nodeFsc := mock_node.NewMockNode_FetchSVIDClient(ctrl)

	client := New(cfg)
	client.newNodeClientCallback = func() (node.NodeClient, error) {
		return nodeClient, nil
	}
	req := &node.FetchSVIDRequest{
		Csrs: [][]byte{{1, 2, 3, 4}},
	}
	res := &node.FetchSVIDResponse{
		SvidUpdate: &node.SvidUpdate{
			Bundle: []byte{10, 20, 30, 40},
			RegistrationEntries: []*common.RegistrationEntry{{
				EntryId: "1",
			}},
			Svids: map[string]*node.Svid{
				"someSpiffeId": {
					SvidCert: []byte{11, 22, 33},
				},
			},
		},
	}

	nodeClient.EXPECT().FetchSVID(gomock.Any()).Return(nodeFsc, nil)
	nodeFsc.EXPECT().Send(req)
	nodeFsc.EXPECT().CloseSend()
	nodeFsc.EXPECT().Recv().Return(res, nil)
	nodeFsc.EXPECT().Recv().Return(nil, io.EOF)

	update, err := client.FetchUpdates(req)
	require.Nil(t, err)

	assert.Equal(t, res.SvidUpdate.Bundle, update.Bundle)
	assert.Equal(t, res.SvidUpdate.Svids, update.SVIDs)
	for _, entry := range res.SvidUpdate.RegistrationEntries {
		assert.Equal(t, entry, update.Entries[entry.EntryId])
	}
	client.Release()
}
