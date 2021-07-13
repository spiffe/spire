package middleware

import (
	"context"

	"github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/policy"
	"github.com/spiffe/spire/pkg/common/telemetry"
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

func WithAuthorization(policyEngine *policy.Engine, entryFetcher EntryFetcher, agentAuthorizer AgentAuthorizer) middleware.Middleware {
	return &authorizationMiddleware{
		policyEngine:    policyEngine,
		entryFetcher:    entryFetcher,
		agentAuthorizer: agentAuthorizer,
	}
}

type authorizationMiddleware struct {
	policyEngine    *policy.Engine
	entryFetcher    EntryFetcher
	agentAuthorizer AgentAuthorizer
}

func (m *authorizationMiddleware) Preprocess(ctx context.Context, methodName string, req interface{}) (context.Context, error) {
	ctx, err := callerContextFromContext(ctx)
	if err != nil {
		return nil, err
	}

	fields := make(logrus.Fields)
	if !rpccontext.CallerIsLocal(ctx) {
		fields[telemetry.CallerAddr] = rpccontext.CallerAddr(ctx).String()
	}
	id, ok := rpccontext.CallerID(ctx)
	if ok {
		fields[telemetry.CallerID] = id.String()
	}
	// Add request ID to logger, it simplify debugging when calling batch endpints
	requestID, err := uuid.NewV4()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create request ID: %v", err)
	}
	fields[telemetry.RequestID] = requestID.String()

	if len(fields) > 0 {
		ctx = rpccontext.WithLogger(ctx, rpccontext.Logger(ctx).WithFields(fields))
	}

	allow, err := m.opaAuth(ctx, req, methodName)
	if err != nil {
		rpccontext.Logger(ctx).WithError(err).Error("Failed to authenticate caller")
		return nil, err
	}
	if allow {
		return ctx, nil
	}

	deniedErr := status.Errorf(codes.PermissionDenied, "Authorization denied for method %v", methodName)
	rpccontext.Logger(ctx).WithError(deniedErr).Error("Failed to authenticate caller")
	return nil, deniedErr
}

func (m *authorizationMiddleware) Postprocess(ctx context.Context, methodName string, handlerInvoked bool, rpcErr error) {
	// Intentionally empty.
}
