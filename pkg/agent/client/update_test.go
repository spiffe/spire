package client

import (
	"testing"

	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/util"
)

var (
	regEntriesMap = util.GetRegistrationEntriesMap("manager_test_entries.json")
)

func TestString(t *testing.T) {
	entries := regEntriesMap["resp1"]
	u := &Update{
		Entries: map[string]*common.RegistrationEntry{entries[0].EntryId: entries[0]},
		SVIDs: map[string]*node.X509SVID{
			"spiffe://example.org": {
				Cert:      []byte{4, 5},
				ExpiresAt: 5,
			},
		},
		Bundles: map[string]*node.Bundle{
			"spiffe://example.org": {
				Id:      "spiffe://example.org",
				CaCerts: []byte{1, 2, 3},
			},
		},
	}

	expected := "{ Entries: [{ spiffeID: spiffe://example.org/spire/agent, parentID: spiffe://example.org/spire/agent/join_token/abcd, selectors: [type:\"spiffe_id\" value:\"spiffe://example.org/spire/agent/join_token/abcd\" ]}], SVIDs: [spiffe://example.org: cert:\"\\004\\005\" expires_at:5  ], Bundles: [spiffe://example.org ]}"
	if u.String() != expected {
		t.Errorf("expected: %s, got: %s", expected, u.String())
	}
}
