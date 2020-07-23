package middleware

import (
	"context"

	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/proto/spire-next/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func AuthorizeDownstream(entryFetcher EntryFetcher) Authorizer {
	return downstreamAuthorizer{entryFetcher: entryFetcher}
}

type downstreamAuthorizer struct {
	entryFetcher EntryFetcher
}

func (a downstreamAuthorizer) Name() string {
	return "downstream"
}

func (a downstreamAuthorizer) AuthorizeCaller(ctx context.Context) (context.Context, error) {
	ctx, entries, err := WithCallerEntries(ctx, a.entryFetcher)
	if err != nil {
		return nil, err
	}

	downstreamEntries := make([]*types.Entry, 0, len(entries))
	for _, entry := range entries {
		if entry.Downstream {
			downstreamEntries = append(downstreamEntries, entry)
		}
	}
	if len(downstreamEntries) == 0 {
		return nil, status.Error(codes.PermissionDenied, "caller is not a downstream workload")
	}

	return rpccontext.WithCallerDownstreamEntries(ctx, downstreamEntries), nil
}
