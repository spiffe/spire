package middleware

import (
	"context"

	"github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/policy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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

	ctx, allow, err := m.opaAuth(ctx, req, methodName)
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
