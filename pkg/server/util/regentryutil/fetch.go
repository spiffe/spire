package regentryutil

import (
	"context"
	"errors"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
)

// FetchRegistrationEntries returns a list of registration entries related to
// an agent. This list consists of any node registration entries with a subset
// of the agent's node selectors. It also consists of any registration entries
// parented (directly or indirectly) to either the agent ID or the node
// registration entries SPIFFE IDs.
func FetchRegistrationEntries(ctx context.Context, ds datastore.DataStore, agentID string) ([]*common.RegistrationEntry, error) {
	mapped, err := fetchNodeEntries(ctx, ds, agentID)
	if err != nil {
		return nil, err
	}

	visited := make(map[string]struct{})

	entries := mapped
	descendants, err := fetchDescendantEntries(ctx, ds, agentID, visited)
	if err != nil {
		return nil, err
	}
	entries = append(entries, descendants...)

	for _, entry := range mapped {
		descendants, err := fetchDescendantEntries(ctx, ds, entry.SpiffeId, visited)
		if err != nil {
			return nil, err
		}
		entries = append(entries, descendants...)
	}

	return util.DedupRegistrationEntries(entries), nil
}

// fetchNodeEntries fetches the node entries applicable to the agent ID, i.e.
// those which have a subset of the agent's node selectors.
func fetchNodeEntries(ctx context.Context, ds datastore.DataStore, agentID string) ([]*common.RegistrationEntry, error) {
	selectorsResp, err := ds.GetNodeSelectors(ctx,
		&datastore.GetNodeSelectorsRequest{
			SpiffeId: agentID,
		})
	if err != nil {
		return nil, err
	}
	if selectorsResp.Selectors == nil {
		return nil, errors.New("response missing selectors")
	}

	// No need to look for more entries if we didn't get any selectors
	selectors := selectorsResp.Selectors.Selectors
	if len(selectors) < 1 {
		return nil, nil
	}

	// list all registration entries with a combination of the selectors
	listResp, err := ds.ListRegistrationEntries(ctx,
		&datastore.ListRegistrationEntriesRequest{
			BySelectors: &datastore.BySelectors{
				Selectors: selectors,
				Match:     datastore.BySelectors_MATCH_SUBSET,
			},
		})
	if err != nil {
		return nil, err
	}

	return listResp.Entries, nil
}

// fetchDescendantEntries recursively determines those registration entries that
// are either directly or indirectly parented by the parentID. A visited map
// is passed and used to prevent traversing parentage cycles.
func fetchDescendantEntries(ctx context.Context, ds datastore.DataStore, parentID string, visited map[string]struct{}) ([]*common.RegistrationEntry, error) {
	if _, ok := visited[parentID]; ok {
		return nil, nil
	}
	visited[parentID] = struct{}{}

	resp, err := ds.ListRegistrationEntries(ctx,
		&datastore.ListRegistrationEntriesRequest{
			ByParentId: &wrappers.StringValue{
				Value: parentID,
			},
		})
	if err != nil {
		return nil, err
	}

	out := resp.Entries
	for _, child := range resp.Entries {
		descendants, err := fetchDescendantEntries(ctx, ds, child.SpiffeId, visited)
		if err != nil {
			return nil, err
		}
		out = append(out, descendants...)
	}

	return out, nil
}
