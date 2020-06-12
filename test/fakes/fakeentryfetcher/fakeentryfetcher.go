package fakeentryfetcher

import (
	"context"
	"errors"

	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/proto/spire-next/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// EntryFetcher is a fake entry fetcher
type EntryFetcher struct {
	Err     string
	Entries []*types.Entry
}

func (f *EntryFetcher) FetchAuthorizedEntries(ctx context.Context) ([]*types.Entry, error) {
	if f.Err != "" {
		return nil, status.Error(codes.Internal, f.Err)
	}

	_, ok := rpccontext.CallerID(ctx)
	if !ok {
		return nil, errors.New("missing caller ID")
	}

	return f.Entries, nil
}
