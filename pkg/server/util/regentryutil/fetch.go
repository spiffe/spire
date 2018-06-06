package regentryutil

import (
	"context"

	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/datastore"
)

func FetchRegistrationEntries(ctx context.Context,
	dataStore datastore.DataStore, spiffeID string) (
	entries []*common.RegistrationEntry, err error) {

	fetcher := newRegistrationEntryFetcher(dataStore)
	return fetcher.Fetch(ctx, spiffeID)
}

type registrationEntryFetcher struct {
	dataStore datastore.DataStore
}

func newRegistrationEntryFetcher(dataStore datastore.DataStore) *registrationEntryFetcher {
	return &registrationEntryFetcher{
		dataStore: dataStore,
	}
}

func (f *registrationEntryFetcher) Fetch(ctx context.Context, id string) ([]*common.RegistrationEntry, error) {
	entries, err := f.fetch(ctx, id, make(map[string]bool))
	if err != nil {
		return nil, err
	}
	return util.DedupRegistrationEntries(entries), nil
}

func (f *registrationEntryFetcher) fetch(ctx context.Context, id string, visited map[string]bool) ([]*common.RegistrationEntry, error) {
	if visited[id] {
		return nil, nil
	}
	visited[id] = true

	directEntries, err := f.directEntries(ctx, id)
	if err != nil {
		return nil, err
	}

	entries := directEntries
	for _, directEntry := range directEntries {
		descendantEntries, err := f.fetch(ctx, directEntry.SpiffeId, visited)
		if err != nil {
			return nil, err
		}
		entries = append(entries, descendantEntries...)
	}

	return entries, nil
}

// directEntries queries the datastore to determine the registration entries
// the provided ID is immediately authorized to issue.
func (f *registrationEntryFetcher) directEntries(ctx context.Context, id string) ([]*common.RegistrationEntry, error) {
	childEntries, err := f.childEntries(ctx, id)
	if err != nil {
		return nil, err
	}

	mappedEntries, err := f.mappedEntries(ctx, id)
	if err != nil {
		return nil, err
	}

	return append(childEntries, mappedEntries...), nil
}

// childEntries returns all registration entries for which the given ID is
// defined as a parent.
func (f *registrationEntryFetcher) childEntries(ctx context.Context, clientID string) ([]*common.RegistrationEntry, error) {
	resp, err := f.dataStore.ListParentIDEntries(ctx,
		&datastore.ListParentIDEntriesRequest{
			ParentId: clientID,
		})
	if err != nil {
		return nil, err
	}

	return resp.RegisteredEntryList, nil
}

// mappedEntries returns all registration entries for which the given ID has
// been mapped to by a node resolver.
func (f *registrationEntryFetcher) mappedEntries(ctx context.Context, clientID string) ([]*common.RegistrationEntry, error) {
	resolveResp, err := f.dataStore.FetchNodeResolverMapEntry(ctx,
		&datastore.FetchNodeResolverMapEntryRequest{
			BaseSpiffeId: clientID,
		})
	if err != nil {
		return nil, err
	}

	selectors := []*common.Selector{}
	for _, entry := range resolveResp.NodeResolverMapEntryList {
		selectors = append(selectors, entry.Selector)
	}

	// No need to look for more entries if we didn't get any selectors
	if len(selectors) < 1 {
		return nil, nil
	}

	listResp, err := f.dataStore.ListMatchingEntries(ctx,
		&datastore.ListSelectorEntriesRequest{
			Selectors: selectors,
		})
	if err != nil {
		return nil, err
	}

	return listResp.RegisteredEntryList, nil
}
