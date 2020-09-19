package entrycache

import (
	"context"
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/types"
)

const (
	agentPageSize = 500
	entryPageSize = 500
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
	ds              datastore.DataStore
	entries         []*types.Entry
	next            int
	err             error
	paginationToken string
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
	if it.entries == nil || (it.next >= len(it.entries) && it.paginationToken != "") {
		req := &datastore.ListRegistrationEntriesRequest{
			TolerateStale: true,
			Pagination: &datastore.Pagination{
				Token:    it.paginationToken,
				PageSize: entryPageSize,
			},
		}

		resp, err := it.ds.ListRegistrationEntries(ctx, req)
		if err != nil {
			it.err = err
			return false
		}

		it.paginationToken = resp.Pagination.Token
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
		if anyAgents := it.fetchAgents(ctx); !anyAgents {
			return false
		}
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
// The request for agent selectors is paginated since the size of the selector data in the datastore
// can be larger than the gRPC maximum message size.
// This means that one Agent's selectors could be split across multiple pages of the response from the datastore.
// Because of this, we need to load all the selectors at once in order to return accurate Agent
// data to the client.
func (it *agentIteratorDS) fetchAgents(ctx context.Context) bool {
	var agents []Agent
	var token string
	var currentID string
	var selectors []*common.Selector
	pushAgent := func(spiffeID string, curSelectors []*common.Selector) {
		switch {
		case currentID == "":
			currentID = spiffeID
		case spiffeID != currentID:
			agent := Agent{
				ID:        spiffeid.RequireFromString(currentID),
				Selectors: api.ProtoFromSelectors(selectors),
			}
			agents = append(agents, agent)
			currentID = spiffeID
			selectors = nil
		}

		selectors = append(selectors, curSelectors...)
	}

	selectorsValidAt := &timestamp.Timestamp{
		Seconds: time.Now().Unix(),
	}

	for {
		req := &datastore.ListNodeSelectorsRequest{
			TolerateStale: true,
			Pagination: &datastore.Pagination{
				Token:    token,
				PageSize: agentPageSize,
			},
			ValidAt: selectorsValidAt,
		}

		resp, err := it.ds.ListNodeSelectors(ctx, req)
		if err != nil {
			it.err = err
			return false
		}

		if len(resp.Selectors) == 0 {
			pushAgent("", nil)
			if len(agents) == 0 {
				return false
			}

			break
		}

		for _, selector := range resp.Selectors {
			pushAgent(selector.SpiffeId, selector.Selectors)
		}

		token = resp.Pagination.Token
	}

	it.agents = agents
	return true
}
