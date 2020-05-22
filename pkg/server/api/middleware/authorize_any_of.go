package middleware

import (
	"context"
	"fmt"
	"strings"

	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func AuthorizeAnyOf(authorizers ...Authorizer) Authorizer {
	names := make([]string, 0, len(authorizers))
	for _, authorizer := range authorizers {
		names = append(names, authorizer.Name())
	}

	return anyOfAuthorizer{
		names:       names,
		authorizers: authorizers,
	}
}

type anyOfAuthorizer struct {
	names       []string
	authorizers []Authorizer
}

func (a anyOfAuthorizer) Name() string {
	return fmt.Sprintf("any-of[%s]", strings.Join(a.names, ","))
}

func (a anyOfAuthorizer) AuthorizeCaller(ctx context.Context) (context.Context, error) {
	if len(a.authorizers) == 0 {
		rpccontext.Logger(ctx).Error("Authorization misconfigured; this is a bug")
		return nil, status.Error(codes.Internal, "authorization misconfigured")
	}

	var authenticated bool
	for _, authorizer := range a.authorizers {
		nextCtx, err := authorizer.AuthorizeCaller(ctx)
		st := status.Convert(err)
		switch st.Code() {
		case codes.OK:
			ctx = nextCtx
			authenticated = true
		case codes.PermissionDenied:
		default:
			return nil, err
		}
	}

	if !authenticated {
		return nil, status.Errorf(codes.PermissionDenied, "caller must be one of %q", a.names)
	}

	return ctx, nil
}
