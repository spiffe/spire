package middleware

import (
	"context"

	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/proto/spire-next/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func AuthorizeAdmin(entryFetcher EntryFetcher) Authorizer {
	return adminAuthorizer{entryFetcher: entryFetcher}
}

type adminAuthorizer struct {
	entryFetcher EntryFetcher
}

func (a adminAuthorizer) Name() string {
	return "admin"
}

func (a adminAuthorizer) AuthorizeCaller(ctx context.Context) (context.Context, error) {
	ctx, entries, err := WithCallerEntries(ctx, a.entryFetcher)
	if err != nil {
		return nil, err
	}

	adminEntries := make([]*types.Entry, 0, len(entries))
	for _, entry := range entries {
		if entry.Admin {
			adminEntries = append(adminEntries, entry)
		}
	}
	if len(adminEntries) == 0 {
		return nil, status.Error(codes.PermissionDenied, "caller is not an admin workload")
	}

	return rpccontext.WithCallerAdminEntries(ctx, adminEntries), nil
}
