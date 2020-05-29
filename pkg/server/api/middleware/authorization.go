package middleware

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Authorizer interface {
	// Name returns the name of the authorizer. The value may be included in
	// logs and messages returned to callers on authorization failure.
	Name() string

	// AuthorizeCaller is called by the authorization middleware to determine
	// if a caller is authorized. The caller is retrievable on the passed in
	// context. On success, the method returns the (potentially embellished)
	// context passed into the function. On failure, the method returns an
	// error and the returned context is ignored.
	AuthorizeCaller(ctx context.Context) (context.Context, error)
}

func WithAuthorization(authorizers map[string]Authorizer) Middleware {
	return &authorizationMiddleware{
		authorizers: authorizers,
	}
}

type authorizationMiddleware struct {
	authorizers map[string]Authorizer
}

func (m *authorizationMiddleware) Preprocess(ctx context.Context, methodName string) (context.Context, error) {
	ctx, err := callerContextFromContext(ctx)
	if err != nil {
		return nil, err
	}

	fields := make(logrus.Fields)
	if !rpccontext.CallerIsLocal(ctx) {
		fields["caller-addr"] = rpccontext.CallerAddr(ctx).String()
	}
	if id, ok := rpccontext.CallerID(ctx); ok {
		fields["caller-id"] = id.String()
	}
	if len(fields) > 0 {
		ctx = rpccontext.WithLogger(ctx, rpccontext.Logger(ctx).WithFields(fields))
	}

	authorizer, ok := m.authorizers[methodName]
	if !ok {
		rpccontext.Logger(ctx).Error("Authorization misconfigured (method not registered); this is a bug")
		return nil, status.Errorf(codes.Internal, "authorization misconfigured for %q (method not registered)", methodName)
	}
	return authorizer.AuthorizeCaller(ctx)
}

func (m *authorizationMiddleware) Postprocess(ctx context.Context, methodName string, handlerInvoked bool, rpcErr error) {
	// Intentionally empty.
}
