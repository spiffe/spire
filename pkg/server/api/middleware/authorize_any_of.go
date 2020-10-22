package middleware

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthorizeAnyOf combines authorizers where if any authorizer succeeds, then
// the caller is authorized. Specifically:
// 1. If any authorizer returns any status code other than OK or
// PERMISSION_DENIED, the authorization fails.
// 2. If all authorizers return PERMISSION_DENIED, then authorization
// fails.
// 3. Otherwise, if at least one authorizer returns OK, authorization
// succeeds.
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
		logMisconfiguration(ctx, "Authorization misconfigured (no authorizers); this is a bug")
		return nil, status.Error(codes.Internal, "authorization misconfigured (no authorizers)")
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
