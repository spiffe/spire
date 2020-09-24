package controllers

import (
	"context"
	"strings"

	"github.com/spiffe/spire/proto/spire/api/server/entry/v1"
	spiretypes "github.com/spiffe/spire/proto/spire/types"
)

func spiffeIDHasPrefix(spiffeID *spiretypes.SPIFFEID, prefix *spiretypes.SPIFFEID) bool {
	return spiffeID != nil && prefix != nil && spiffeID.TrustDomain == prefix.TrustDomain && strings.HasPrefix(spiffeID.Path, prefix.Path)
}

func listEntries(ctx context.Context, client entry.EntryClient, filter *entry.ListEntriesRequest_Filter) ([]*spiretypes.Entry, error) {
	nextPageToken := ""
	var entries []*spiretypes.Entry
	for {
		listResponse, err := client.ListEntries(ctx, &entry.ListEntriesRequest{Filter: filter, PageToken: nextPageToken})
		if err != nil {
			return nil, err
		}
		entries = append(entries, listResponse.Entries...)
		nextPageToken = listResponse.NextPageToken
		if nextPageToken == "" {
			break
		}
	}
	return entries, nil
}

func spiffeIDsEqual(a *spiretypes.SPIFFEID, b *spiretypes.SPIFFEID) bool {
	return (a == b) || (a != nil && b != nil && a.GetTrustDomain() == b.GetTrustDomain() && a.GetPath() == b.GetPath())
}
