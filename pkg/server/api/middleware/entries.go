package middleware

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/proto/spire-next/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type EntryFetcher interface {
	// FetchEntries fetches the downstream entries matching the given SPIFFE ID.
	FetchEntries(ctx context.Context, id spiffeid.ID) ([]*types.Entry, error)
}

// EntryFetcherFunc implements EntryFetcher with a function
type EntryFetcherFunc func(ctx context.Context, id spiffeid.ID) ([]*types.Entry, error)

// FetchEntries fetches the downstream entries matching the given SPIFFE ID.
func (fn EntryFetcherFunc) FetchEntries(ctx context.Context, id spiffeid.ID) ([]*types.Entry, error) {
	return fn(ctx, id)
}

type callerEntriesKey struct{}

// WithCallerEntries returns a the caller entries retrieved using the given
// fetcher. If the context already has the caller entries, they are returned
// without re-fetching. This reduces entry fetching in the face of multiple
// authorizers.
func WithCallerEntries(ctx context.Context, entryFetcher EntryFetcher) (context.Context, []*types.Entry, error) {
	if entries, ok := ctx.Value(callerEntriesKey{}).([]*types.Entry); ok {
		return ctx, entries, nil
	}

	var entries []*types.Entry
	id, ok := rpccontext.CallerID(ctx)
	if !ok {
		return ctx, nil, nil
	}

	entries, err := entryFetcher.FetchEntries(ctx, id)
	if err != nil {
		rpccontext.Logger(ctx).WithError(err).Error("Failed to fetch caller entries")
		return nil, nil, status.Errorf(codes.Internal, "failed to fetch caller entries: %v", err)
	}
	return context.WithValue(ctx, callerEntriesKey{}, entries), entries, nil
}
