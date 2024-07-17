package endpoints

import (
	"context"
	"sort"
	"strconv"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/stretchr/testify/require"
)

func TestBuildRegistrationEntriesCache(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)

	agentID, err := spiffeid.FromString("spiffe://example.org/myagent")
	require.NoError(t, err)

	// Create registration entries
	numEntries := 10
	for i := 0; i < numEntries; i++ {
		_, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
			SpiffeId: "spiffe://example.org/workload" + strconv.Itoa(i),
			ParentId: agentID.String(),
			Selectors: []*common.Selector{
				{
					Type:  "workload",
					Value: "one",
				},
			},
		})
		require.NoError(t, err)
	}

	for _, tt := range []struct {
		name     string
		pageSize int32
		err      string
	}{
		{
			name:     "Page size of 0",
			pageSize: 0,
			err:      "cannot paginate with pagesize = 0",
		},
		{
			name:     "Page size of half the entries",
			pageSize: int32(numEntries / 2),
		},
		{
			name:     "Page size of all the entries",
			pageSize: int32(numEntries),
		},
		{
			name:     "Page size of all the entries + 1",
			pageSize: int32(numEntries + 1),
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			cache := authorizedentries.NewCache(clk)
			registrationEntries, err := buildRegistrationEntriesCache(ctx, log, ds, clk, cache, tt.pageSize)
			if tt.err != "" {
				require.ErrorContains(t, err, tt.err)
				return
			}

			require.NoError(t, err)
			require.True(t, registrationEntries.receivedFirstEvent)

			entries := cache.GetAuthorizedEntries(agentID)
			require.Equal(t, numEntries, len(entries))

			spiffeIDs := make([]string, 0, numEntries)
			for _, entry := range entries {
				spiffeID, err := idutil.IDFromProto(entry.SpiffeId)
				require.NoError(t, err)
				spiffeIDs = append(spiffeIDs, spiffeID.String())
			}
			sort.Strings(spiffeIDs)

			for i, spiffeID := range spiffeIDs {
				require.Equal(t, "spiffe://example.org/workload"+strconv.Itoa(i), spiffeID)
			}
		})
	}
}

func TestRegistrationEntriesCacheMissedEventNotFound(t *testing.T) {
	ctx := context.Background()
	log, hook := test.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)
	cache := authorizedentries.NewCache(clk)

	registrationEntries, err := buildRegistrationEntriesCache(ctx, log, ds, clk, cache, buildCachePageSize)
	require.NoError(t, err)
	require.NotNil(t, registrationEntries)

	registrationEntries.missedEvents[1] = clk.Now()
	registrationEntries.replayMissedEvents(ctx)
	require.Equal(t, "Event not yet populated in database", hook.LastEntry().Message)
}
