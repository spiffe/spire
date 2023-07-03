package middleware

import (
	"context"

	"github.com/gofrs/uuid/v5"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/authpolicy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func WithAuthorization(authPolicyEngine *authpolicy.Engine, entryFetcher EntryFetcher, agentAuthorizer AgentAuthorizer, adminIDs []spiffeid.ID) middleware.Middleware {
	return &authorizationMiddleware{
		authPolicyEngine: authPolicyEngine,
		entryFetcher:     entryFetcher,
		agentAuthorizer:  agentAuthorizer,
		adminIDs:         adminIDSet(adminIDs),
	}
}

type authorizationMiddleware struct {
	authPolicyEngine *authpolicy.Engine
	entryFetcher     EntryFetcher
	agentAuthorizer  AgentAuthorizer
	adminIDs         map[spiffeid.ID]struct{}
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
	if id, ok := rpccontext.CallerID(ctx); ok {
		fields[telemetry.CallerID] = id.String()
	}
	// Add request ID to logger, it simplifies debugging when calling batch endpoints
	requestID, err := uuid.NewV4()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create request ID: %v", err)
	}
	fields[telemetry.RequestID] = requestID.String()

	if len(fields) > 0 {
		ctx = rpccontext.WithLogger(ctx, rpccontext.Logger(ctx).WithFields(fields))
	}

	var deniedDetails *types.PermissionDeniedDetails
	authCtx, allow, err := m.opaAuth(ctx, req, methodName)
	if err != nil {
		statusErr := status.Convert(err)
		if statusErr.Code() != codes.PermissionDenied {
			rpccontext.Logger(ctx).WithError(err).Error("Authorization failure from OPA auth")
			return nil, err
		}

		deniedDetails = deniedDetailsFromStatus(statusErr)
	}
	if allow {
		return authCtx, nil
	}

	st := status.Newf(codes.PermissionDenied, "authorization denied for method %s", methodName)
	if deniedDetails != nil {
		st, err = st.WithDetails(deniedDetails)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to add denied details to error: %v", err)
		}
	}

	deniedErr := st.Err()
	rpccontext.Logger(ctx).WithError(deniedErr).Error("Failed to authenticate caller")
	return nil, deniedErr
}

func (m *authorizationMiddleware) Postprocess(context.Context, string, bool, error) {
	// Intentionally empty.
}

func adminIDSet(ids []spiffeid.ID) map[spiffeid.ID]struct{} {
	set := make(map[spiffeid.ID]struct{})
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return set
}

func deniedDetailsFromStatus(s *status.Status) *types.PermissionDeniedDetails {
	for _, detail := range s.Details() {
		reason, ok := detail.(*types.PermissionDeniedDetails)
		if ok {
			return reason
		}
	}

	return nil
}
