package entrycache

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEntryIteratorDS(t *testing.T) {
	ds := fakedatastore.New(t)
	ctx := context.Background()

	t.Run("no entries", func(t *testing.T) {
		it := makeEntryIteratorDS(ds)
		assert.False(t, it.Next(ctx))
		assert.NoError(t, it.Err())
	})

	// Create some entries.
	// Set listEntriesRequestPageSize to 10 so that unit tests don't have to generate a huge number of entries in-memory.
	listEntriesRequestPageSize = 10
	numEntries := int(listEntriesRequestPageSize) + 1
	const parentID = "spiffe://example.org/parent"
	const spiffeIDPrefix = "spiffe://example.org/entry"
	selectors := []*common.Selector{
		{Type: "doesn't", Value: "matter"},
	}
	entriesToCreate := make([]*common.RegistrationEntry, numEntries)
	for i := 0; i < numEntries; i++ {
		entriesToCreate[i] = &common.RegistrationEntry{
			ParentId:  parentID,
			SpiffeId:  spiffeIDPrefix + strconv.Itoa(i),
			Selectors: selectors,
		}
	}

	expectedEntries := make([]*types.Entry, len(entriesToCreate))
	for i, e := range entriesToCreate {
		createdEntry := createRegistrationEntry(ctx, t, ds, e)
		var err error
		expectedEntries[i], err = api.RegistrationEntryToProto(createdEntry)
		require.NoError(t, err)
	}

	t.Run("existing entries - multiple pages", func(t *testing.T) {
		it := makeEntryIteratorDS(ds)
		var entries []*types.Entry

		for i := 0; i < numEntries; i++ {
			assert.True(t, it.Next(ctx))
			require.NoError(t, it.Err())

			entry := it.Entry()
			require.NotNil(t, entry)
			entries = append(entries, entry)
		}

		assert.False(t, it.Next(ctx))
		assert.NoError(t, it.Err())
		assert.ElementsMatch(t, expectedEntries, entries)
	})

	t.Run("datastore error", func(t *testing.T) {
		it := makeEntryIteratorDS(ds)
		for i := 0; i < int(listEntriesRequestPageSize); i++ {
			assert.True(t, it.Next(ctx))
			require.NoError(t, it.Err())
		}
		dsErr := errors.New("some datastore error")
		ds.SetNextError(dsErr)
		assert.False(t, it.Next(ctx))
		assert.Error(t, it.Err())
		// it.Next() returns false after encountering an error on previous call to Next()
		assert.False(t, it.Next(ctx))
	})
}

func TestAgentIteratorDS(t *testing.T) {
	ds := fakedatastore.New(t)
	ctx := context.Background()

	t.Run("no entries", func(t *testing.T) {
		it := makeAgentIteratorDS(ds)
		assert.False(t, it.Next(ctx))
		assert.NoError(t, it.Err())
	})

	const numAgents = 10
	selectors := []*common.Selector{
		{Type: "a", Value: "1"},
		{Type: "b", Value: "2"},
		{Type: "c", Value: "3"},
	}

	expectedSelectors := api.ProtoFromSelectors(selectors)
	expectedAgents := make([]Agent, numAgents)
	for i := 0; i < numAgents; i++ {
		iterStr := strconv.Itoa(i)
		agentID, err := spiffeid.FromString("spiffe://example.org/spire/agent/agent" + iterStr)
		require.NoError(t, err)

		agentIDStr := agentID.String()
		node := &common.AttestedNode{
			SpiffeId:            agentIDStr,
			AttestationDataType: testNodeAttestor,
			CertSerialNumber:    iterStr,
			CertNotAfter:        time.Now().Add(24 * time.Hour).Unix(),
		}

		createAttestedNode(t, ds, node)
		setNodeSelectors(ctx, t, ds, agentIDStr, selectors...)
		expectedAgents[i] = Agent{
			ID:        agentID,
			Selectors: expectedSelectors,
		}
	}

	t.Run("multiple pages", func(t *testing.T) {
		it := makeAgentIteratorDS(ds)
		agents := make([]Agent, numAgents)
		for i := 0; i < numAgents; i++ {
			assert.True(t, it.Next(ctx))
			assert.NoError(t, it.Err())
			agents[i] = it.Agent()
		}

		assert.False(t, it.Next(ctx))
		require.NoError(t, it.Err())
		assert.ElementsMatch(t, expectedAgents, agents)
	})

	t.Run("datastore error", func(t *testing.T) {
		it := makeAgentIteratorDS(ds)
		ds.SetNextError(errors.New("some datastore error"))
		assert.False(t, it.Next(ctx))
		assert.Error(t, it.Err())
		// it.Next() returns false after encountering an error on previous call to Next()
		assert.False(t, it.Next(ctx))
	})
}

func createAttestedNode(t testing.TB, ds datastore.DataStore, node *common.AttestedNode) {
	_, err := ds.CreateAttestedNode(context.Background(), node)
	require.NoError(t, err)
}
