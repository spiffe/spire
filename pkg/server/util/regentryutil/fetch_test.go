package regentryutil

import (
	"context"
	"testing"

	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/stretchr/testify/assert"
)

var (
	ctx = context.Background()
)

func TestFetchRegistrationEntries(t *testing.T) {
	assert := assert.New(t)
	dataStore := fakedatastore.New()

	createRegistrationEntry := func(entry *common.RegistrationEntry) *common.RegistrationEntry {
		resp, err := dataStore.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{
			Entry: entry,
		})
		assert.NoError(err)
		return resp.Entry
	}

	setNodeSelectors := func(spiffeID string, selectors ...*common.Selector) {
		_, err := dataStore.SetNodeSelectors(ctx, &datastore.SetNodeSelectorsRequest{
			Selectors: &datastore.NodeSelectors{
				SpiffeId:  spiffeID,
				Selectors: selectors,
			},
		})
		assert.NoError(err)
	}

	var (
		agentID = "spiffe://example.org/agent"
		oneID   = "spiffe://example.org/1"
		twoID   = "spiffe://example.org/2"
		threeID = "spiffe://example.org/3"
		fourID  = "spiffe://example.org/4"
		fiveID  = "spiffe://example.org/5"
		sixID   = "spiffe://example.org/6"
		sevenID = "spiffe://example.org/7"
		eightID = "spiffe://example.org/8"
		nineID  = "spiffe://example.org/9"
	)

	a1 := &common.Selector{Type: "a", Value: "1"}
	b2 := &common.Selector{Type: "b", Value: "2"}
	c3 := &common.Selector{Type: "c", Value: "3"}
	d4 := &common.Selector{Type: "d", Value: "4"}

	//            ------------------> 6         9
	//           /                   /
	//          /                   7
	//        agent ---------> 4     \
	//        /   \           /       8
	//       1     2         5
	//        \   /
	//          3
	//
	// node selectors on agent (a1, b2, c3) are a superset of those set on 4
	// (a1, b2).

	oneEntry := createRegistrationEntry(&common.RegistrationEntry{
		ParentId: agentID,
		SpiffeId: oneID,
	})

	twoEntry := createRegistrationEntry(&common.RegistrationEntry{
		ParentId: agentID,
		SpiffeId: twoID,
	})

	threeOneEntry := createRegistrationEntry(&common.RegistrationEntry{
		ParentId: oneID,
		SpiffeId: threeID,
	})

	threeTwoEntry := createRegistrationEntry(&common.RegistrationEntry{
		ParentId: twoID,
		SpiffeId: threeID,
	})

	fourEntry := createRegistrationEntry(&common.RegistrationEntry{
		SpiffeId:  fourID,
		Selectors: []*common.Selector{a1, b2},
	})

	fiveEntry := createRegistrationEntry(&common.RegistrationEntry{
		ParentId: fourID,
		SpiffeId: fiveID,
	})

	sixEntry := createRegistrationEntry(&common.RegistrationEntry{
		SpiffeId:  sixID,
		Selectors: []*common.Selector{b2, c3},
	})

	sevenEntry := createRegistrationEntry(&common.RegistrationEntry{
		ParentId: sixID,
		SpiffeId: sevenID,
	})

	eightEntry := createRegistrationEntry(&common.RegistrationEntry{
		ParentId: sevenID,
		SpiffeId: eightID,
	})

	createRegistrationEntry(&common.RegistrationEntry{
		SpiffeId:  nineID,
		Selectors: []*common.Selector{d4},
	})

	setNodeSelectors(agentID, a1, b2, c3)

	actual, err := FetchRegistrationEntries(ctx, dataStore, agentID)
	assert.NoError(err)

	assert.Equal([]*common.RegistrationEntry{
		oneEntry,
		twoEntry,
		threeOneEntry,
		threeTwoEntry,
		fourEntry,
		fiveEntry,
		sixEntry,
		sevenEntry,
		eightEntry,
	}, actual)

	// Now fetch entries for two. Should just be 3 since 2 has no node
	// selectors that would bring in additional branches.
	actual, err = FetchRegistrationEntries(ctx, dataStore, twoID)
	assert.NoError(err)

	assert.Equal([]*common.RegistrationEntry{
		threeTwoEntry,
	}, actual)
}
