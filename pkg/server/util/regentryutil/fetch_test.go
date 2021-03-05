package regentryutil

import (
	"context"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/cache/entrycache"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	ctx = context.Background()
)

func TestFetchRegistrationEntries(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	dataStore := fakedatastore.New(t)

	cache, err := entrycache.NewFetchX509SVIDCache(10)
	assert.NoError(err)

	createRegistrationEntry := func(entry *common.RegistrationEntry) *common.RegistrationEntry {
		resp, err := dataStore.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{
			Entry: entry,
		})
		require.NoError(err)
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

	rootID := "spiffe://example.org/root"
	oneID := "spiffe://example.org/1"
	twoID := "spiffe://example.org/2"
	threeID := "spiffe://example.org/3"
	fourID := "spiffe://example.org/4"
	fiveID := "spiffe://example.org/5"
	someParentID := "spiffe://example.org/parent"

	a1 := &common.Selector{Type: "a", Value: "1"}
	b2 := &common.Selector{Type: "b", Value: "2"}

	//
	//        root             4(a1,b2)
	//        /   \           /
	//       1     2         5
	//            /
	//           3
	//
	// node resolvers map from 2 to 4

	oneEntry := createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  rootID,
		SpiffeId:  oneID,
		Selectors: []*common.Selector{{Type: "not", Value: "relevant"}},
	})

	twoEntry := createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  rootID,
		SpiffeId:  twoID,
		Selectors: []*common.Selector{{Type: "not", Value: "relevant"}},
	})

	threeEntry := createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  twoID,
		SpiffeId:  threeID,
		Selectors: []*common.Selector{{Type: "not", Value: "relevant"}},
	})

	fourEntry := createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  someParentID,
		SpiffeId:  fourID,
		Selectors: []*common.Selector{a1, b2},
	})

	fiveEntry := createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  fourID,
		SpiffeId:  fiveID,
		Selectors: []*common.Selector{{Type: "not", Value: "relevant"}},
	})

	setNodeSelectors(twoID, a1, b2)

	expected := []*common.RegistrationEntry{
		oneEntry,
		twoEntry,
		threeEntry,
		fourEntry,
		fiveEntry,
	}

	actual, err := FetchRegistrationEntriesWithCache(ctx, dataStore, cache, spiffeid.RequireFromString(rootID))
	assert.NoError(err)

	assert.Equal(expected, actual)
}
