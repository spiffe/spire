package entrycache

import (
	"context"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/types"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	_ EntryIterator = (*entryIteratorDS)(nil)
	_ AgentIterator = (*agentIteratorDS)(nil)
)

// BuildFromDataStore builds a Cache using the provided datastore as the data source
func BuildFromDataStore(ctx context.Context, ds datastore.DataStore) (*FullEntryCache, error) {
	return Build(ctx, makeEntryIteratorDS(ds), makeAgentIteratorDS(ds))
}

type entryIteratorDS struct {
	ds      datastore.DataStore
	entries []*types.Entry
	next    int
	err     error
}

func makeEntryIteratorDS(ds datastore.DataStore) EntryIterator {
	return &entryIteratorDS{
		ds: ds,
	}
}

func (it *entryIteratorDS) Next(ctx context.Context) bool {
	if it.err != nil {
		return false
	}
	if it.entries == nil {
		req := &datastore.ListRegistrationEntriesRequest{
			TolerateStale: true,
		}

		resp, err := it.ds.ListRegistrationEntries(ctx, req)
		if err != nil {
			it.err = err
			return false
		}

		resp.Entries = it.filterEntries(resp.Entries)

		it.next = 0
		it.entries, err = api.RegistrationEntriesToProto(resp.Entries)
		if err != nil {
			it.err = err
			return false
		}
	}
	if it.next >= len(it.entries) {
		return false
	}
	it.next++
	return true
}

func (it *entryIteratorDS) filterEntries(in []*common.RegistrationEntry) []*common.RegistrationEntry {
	out := make([]*common.RegistrationEntry, 0, len(in))
	for _, entry := range in {
		// Filter out entries with invalid SPIFFE IDs. Operators are notified
		// that they are ignored on server startup (see
		// pkg/server/scanentries.go)
		if err := idutil.CheckIDStringNormalization(entry.SpiffeId); err != nil {
			continue
		}
		if err := idutil.CheckIDStringNormalization(entry.ParentId); err != nil {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func (it *entryIteratorDS) Entry() *types.Entry {
	return it.entries[it.next-1]
}

func (it *entryIteratorDS) Err() error {
	return it.err
}

type agentIteratorDS struct {
	ds     datastore.DataStore
	agents []Agent
	next   int
	err    error
}

func makeAgentIteratorDS(ds datastore.DataStore) AgentIterator {
	return &agentIteratorDS{
		ds: ds,
	}
}

func (it *agentIteratorDS) Next(ctx context.Context) bool {
	if it.err != nil {
		return false
	}
	if it.agents == nil {
		agents, err := it.fetchAgents(ctx)
		if err != nil {
			it.err = err
			return false
		}
		it.agents = agents
	}
	if it.next >= len(it.agents) {
		return false
	}
	it.next++
	return true
}

func (it *agentIteratorDS) Agent() Agent {
	return it.agents[it.next-1]
}

func (it *agentIteratorDS) Err() error {
	return it.err
}

// Fetches all agent selectors from the datastore and stores them in the iterator.
func (it *agentIteratorDS) fetchAgents(ctx context.Context) ([]Agent, error) {
	resp, err := it.ds.ListNodeSelectors(ctx, &datastore.ListNodeSelectorsRequest{
		TolerateStale: true,
		ValidAt: &timestamppb.Timestamp{
			Seconds: time.Now().Unix(),
		},
	})
	if err != nil {
		return nil, err
	}

	agents := make([]Agent, 0, len(resp.Selectors))
	for _, selector := range resp.Selectors {
		agentID, err := spiffeid.FromString(selector.SpiffeId)
		if err != nil {
			return nil, err
		}
		agents = append(agents, Agent{
			ID:        agentID,
			Selectors: api.ProtoFromSelectors(selector.Selectors),
		})
	}
	return agents, nil
}
