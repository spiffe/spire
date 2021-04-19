package controllers

import (
	"context"
	"strings"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	spiretypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

func spiffeIDHasPrefix(spiffeID *spiretypes.SPIFFEID, prefix *spiretypes.SPIFFEID) bool {
	return spiffeID != nil && prefix != nil && spiffeID.TrustDomain == prefix.TrustDomain && strings.HasPrefix(spiffeID.Path, prefix.Path)
}

func listEntries(ctx context.Context, client entryv1.EntryClient, filter *entryv1.ListEntriesRequest_Filter) ([]*spiretypes.Entry, error) {
	nextPageToken := ""
	var entries []*spiretypes.Entry
	for {
		listResponse, err := client.ListEntries(ctx, &entryv1.ListEntriesRequest{Filter: filter, PageToken: nextPageToken, PageSize: 1000})
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
