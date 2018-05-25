package client

import (
	"io"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/mock/proto/api/node"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	regEntriesMap = util.GetRegistrationEntriesMap("manager_test_entries.json")
	log, _        = test.NewNullLogger()
)

func TestString(t *testing.T) {
	entries := regEntriesMap["resp1"]
	u := &Update{
		Bundle:  []byte{1, 2, 3},
		Entries: map[string]*common.RegistrationEntry{entries[0].EntryId: entries[0]},
		SVIDs: map[string]*node.Svid{
			"spiffe://example.org": {
				SvidCert: []byte{4, 5},
				Ttl:      5,
			},
		},
	}

	expected := "{ Entries: [{ spiffeID: spiffe://example.org/spire/agent, parentID: spiffe://example.org/spire/agent/join_token/abcd, selectors: [type:\"spiffe_id\" value:\"spiffe://example.org/spire/agent/join_token/abcd\" ]}], SVIDs: [spiffe://example.org: svid_cert:\"\\004\\005\" ttl:5  ], Bundle: bytes}"
	if u.String() != expected {
		t.Errorf("expected: %s, got: %s", expected, u.String())
	}
}

func TestFetchUpdates(t *testing.T) {
	cfg := &Config{
		Log: log,
	}

	ctrl := gomock.NewController(t)
	nodeClient := mock_node.NewMockNodeClient(ctrl)
	nodeFsc := mock_node.NewMockNode_FetchSVIDClient(ctrl)

	client := New(cfg)
	client.getNodeClientCallback = func() (node.NodeClient, error) {
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
