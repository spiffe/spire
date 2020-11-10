package entrycache

import (
	"context"
	"errors"
	"io/ioutil"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHydrator(t *testing.T) {
	ds := fakedatastore.New(t)
	cache := newCacheFromDatastore(ds)
	log := logrus.New()
	log.Out = ioutil.Discard
	metrics := telemetry.Blackhole{}

	cfg := &HydratorConfig{
		EntryCache: cache,
		Log:        log,
		Metrics:    metrics,
	}

	hydrator := NewHydrator(cfg)
	assert.NotNil(t, hydrator)
}

func TestHydrator(t *testing.T) {
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)
	cache := newCacheFromDatastore(ds)
	log := logrus.New()
	log.Out = ioutil.Discard
	metrics := telemetry.Blackhole{}
	interval := 1 * time.Second

	cfg := &HydratorConfig{
		Clock:      clk,
		EntryCache: cache,
		Interval:   interval,
		Log:        log,
		Metrics:    metrics,
	}

	hydrator := NewHydrator(cfg)
	require.NotNil(t, hydrator)

	var hydratorErr error
	startingHydration := make(chan struct{}, 1)
	hydratorDone := make(chan bool, 1)
	ctx, cancel := context.WithCancel(context.Background())
	ds.SetNextError(errors.New("datastore error that fails cache hydration"))
	go func() {
		startingHydration <- struct{}{}
		hydratorErr = hydrator.Run(ctx)
		hydratorDone <- true
	}()

	<-startingHydration
	time.Sleep(time.Millisecond)
	assert.True(t, cache.Initialized())

	const rootID = "spiffe://example.org/root"
	agentSpiffeID, err := spiffeid.FromString(rootID)
	require.NoError(t, err)
	assert.Empty(t, cache.GetAuthorizedEntries(agentSpiffeID))

	// Add some entries to show that the hydrator is running on the configured interval
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
			ParentId:  rootID,
			SpiffeId:  entryIDs[0],
			Selectors: irrelevantSelectors,
		},
		{
			ParentId:  rootID,
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
	irrelevantAgentSelector := &common.Selector{
		Type:  "not",
		Value: "relevant",
	}

	setNodeSelectors(ctx, t, ds, entryIDs[1], irrelevantAgentSelector)

	expected, err := api.RegistrationEntriesToProto(entries)
	require.NoError(t, err)

	// Advance the clock to only half the configured interval. The hydrator should not have run again yet.
	clk.Add(interval / 2)
	assert.Empty(t, cache.GetAuthorizedEntries(agentSpiffeID))

	// Advance the clock to half the configured interval again.
	// This should cause the hydrator to run again.
	clk.Add(interval / 2)
	time.Sleep(time.Millisecond)
	authorizedEntries := cache.GetAuthorizedEntries(agentSpiffeID)
	assert.Equal(t, expected, authorizedEntries)

	cancel()
	assert.True(t, <-hydratorDone)
	assert.NoError(t, hydratorErr)
}
