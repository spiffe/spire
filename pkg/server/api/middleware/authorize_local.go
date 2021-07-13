package middleware

import (
	"context"

	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func AuthorizeLocal() Authorizer {
	return localAuthorizer{}
}

type localAuthorizer struct{}

func (localAuthorizer) Name() string {
	return "local"
}

func (localAuthorizer) AuthorizeCaller(ctx context.Context) (context.Context, error) {
	if !rpccontext.CallerIsLocal(ctx) {
		return nil, status.Error(codes.PermissionDenied, "caller is not local")
	}
	return ctx, nil
}
