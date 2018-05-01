package manager

import (
	"github.com/spiffe/spire/proto/api/node"
	"testing"

	"github.com/spiffe/spire/proto/common"
)

func TestString(t *testing.T) {
	entries := regEntriesMap["resp1"]
	u := &update{
		lastBundle: []byte{1, 2, 3},
		regEntries: map[string]*common.RegistrationEntry{entries[0].EntryId: entries[0]},
		svids: map[string]*node.Svid{
			"spiffe://example.org": {
				SvidCert: []byte{4, 5},
				Ttl:      5,
			},
		},
	}

	expected := "{ regEntries: [{ spiffeID: spiffe://example.org/spire/agent, parentID: spiffe://example.org/spire/agent/join_token/abcd, selectors: [type:\"spiffe_id\" value:\"spiffe://example.org/spire/agent/join_token/abcd\" ]}], svids: [spiffe://example.org: svid_cert:\"\\004\\005\" ttl:5  ], lastBundle: bytes}"
	if u.String() != expected {
		t.Errorf("expected: %s, got: %s", expected, u.String())
	}
}
