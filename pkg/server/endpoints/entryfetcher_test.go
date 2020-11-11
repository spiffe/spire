package endpoints

import (
	"context"
	"errors"
	"io/ioutil"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	spiffeScheme = "spiffe"
	trustDomain  = "example.org"
)

func TestNewAuthorizedEntryFetcherWithFullCache(t *testing.T) {
	ctx := context.Background()
	log := logrus.New()
	log.Out = ioutil.Discard
	metrics := fakemetrics.New()
	ds := fakedatastore.New(t)
	clk := clock.NewMock()

	ef, err := NewAuthorizedEntryFetcherWithFullCache(ctx, log, metrics, ds, clk)
	assert.NoError(t, err)
	assert.NotNil(t, ef)
}

func TestNewAuthorizedEntryFetcherWithFullCacheErrorBuildingCache(t *testing.T) {
	ctx := context.Background()
	log := logrus.New()
	log.Out = ioutil.Discard
	metrics := fakemetrics.New()
	ds := fakedatastore.New(t)
	ds.SetNextError(errors.New("some datastore error"))
	clk := clock.NewMock()

	ef, err := NewAuthorizedEntryFetcherWithFullCache(ctx, log, metrics, ds, clk)
	assert.Error(t, err)
	assert.Nil(t, ef)
}

func TestFetchRegistrationEntries(t *testing.T) {
	ctx := context.Background()
	log := logrus.New()
	log.Out = ioutil.Discard
	metrics := fakemetrics.New()
	ds := fakedatastore.New(t)
	clk := clock.NewMock()
	const rootID = "spiffe://example.org/root"
	expected := setupExpectedEntriesData(ctx, t, ds, rootID)

	ef, err := NewAuthorizedEntryFetcherWithFullCache(ctx, log, metrics, ds, clk)
	require.NoError(t, err)
	require.NotNil(t, ef)

	agentSpiffeID, err := spiffeid.FromString(rootID)
	require.NoError(t, err)

	entries, err := ef.FetchAuthorizedEntries(ctx, agentSpiffeID)
	assert.NoError(t, err)
	assert.Equal(t, expected, entries)
}

func TestRunRebuildCacheTask(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	log := logrus.New()
	log.Out = ioutil.Discard
	metrics := fakemetrics.New()
	ds := fakedatastore.New(t)
	clk := clock.NewMock()
	const rootID = "spiffe://example.org/root"
	agentSpiffeID, err := spiffeid.FromString(rootID)
	require.NoError(t, err)

	ef, err := NewAuthorizedEntryFetcherWithFullCache(ctx, log, metrics, ds, clk)
	require.NoError(t, err)
	require.NotNil(t, ef)

	errChan := make(chan error, 1)
	go func() {
		errChan <- ef.RunRebuildCacheTask(ctx)
	}()

	entries, err := ef.FetchAuthorizedEntries(ctx, agentSpiffeID)
	assert.NoError(t, err)
	assert.Empty(t, entries)

	expected := setupExpectedEntriesData(ctx, t, ds, rootID)

	// Entries should still not be in the cache yet
	// because the clock has not elapsed long enough for the cache rebuild task to execute.
	entries, err = ef.FetchAuthorizedEntries(ctx, agentSpiffeID)
	assert.NoError(t, err)
	assert.Empty(t, entries)

	// Verify that rebuild task gracefully handles downstream errors and retries after the reload interval elapses again
	ds.SetNextError(errors.New("some datastore error"))
	clk.Add(cacheReloadInterval)
	entries, err = ef.FetchAuthorizedEntries(ctx, agentSpiffeID)
	assert.NoError(t, err)
	assert.Empty(t, entries)

	// When the rebuild task is able to complete successfully,
	// the cache should now contain the Agent's new authorized entries
	clk.Add(cacheReloadInterval)
	entries, err = ef.FetchAuthorizedEntries(ctx, agentSpiffeID)
	assert.NoError(t, err)
	assert.Equal(t, expected, entries)

	cancel()
	assert.NoError(t, <-errChan)
}

func setupExpectedEntriesData(ctx context.Context, t *testing.T, ds datastore.DataStore, agentSpiffeID string) []*types.Entry {
	const numEntries = 2
	entryIDs := make([]string, numEntries)
	for i := 0; i < numEntries; i++ {
		entryIDURI := url.URL{
			Scheme: spiffeScheme,
			Host:   trustDomain,
			Path:   strconv.Itoa(i),
		}

		entryIDs[i] = entryIDURI.String()
	}

	irrelevantSelectors := []*common.Selector{
		{
			Type:  "foo",
			Value: "bar",
		},
	}

	entriesToCreate := []*common.RegistrationEntry{
		{
			ParentId:  agentSpiffeID,
			SpiffeId:  entryIDs[0],
			Selectors: irrelevantSelectors,
		},
		{
			ParentId:  agentSpiffeID,
			SpiffeId:  entryIDs[1],
			Selectors: irrelevantSelectors,
		},
	}

	entries := make([]*common.RegistrationEntry, len(entriesToCreate))
	for i, e := range entriesToCreate {
		entries[i] = createRegistrationEntry(ctx, t, ds, e)
	}

	node := &common.AttestedNode{
		SpiffeId:            entryIDs[1],
		AttestationDataType: "test-nodeattestor",
		CertSerialNumber:    "node-1",
		CertNotAfter:        time.Now().Add(24 * time.Hour).Unix(),
	}

	createAttestedNode(t, ds, node)
	irrelevantAgentSelectors := []*common.Selector{
		{
			Type:  "not",
			Value: "relevant",
		},
	}

	entry1SpiffeID, err := spiffeid.FromString(entryIDs[1])
	require.NoError(t, err)

	setNodeSelectors(t, ds, entry1SpiffeID, irrelevantAgentSelectors)

	expected, err := api.RegistrationEntriesToProto(entries)
	require.NoError(t, err)

	return expected
}

func createRegistrationEntry(ctx context.Context, tb testing.TB, ds datastore.DataStore, entry *common.RegistrationEntry) *common.RegistrationEntry {
	resp, err := ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{
		Entry: entry,
	})
	require.NoError(tb, err)
	return resp.Entry
}
