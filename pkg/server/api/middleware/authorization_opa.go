package middleware

import (
	"context"
	"errors"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/authpolicy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (m *authorizationMiddleware) opaAuth(ctx context.Context, req interface{}, fullMethod string) (context.Context, bool, error) {
	if m.authPolicyEngine == nil {
		return ctx, false, errors.New("no policy engine object found")
	}

	// Get SPIFFE ID
	var spiffeID string
	id, ok := rpccontext.CallerID(ctx)
	if ok {
		spiffeID = id.String()
	}

	input := authpolicy.Input{
		Caller:     spiffeID,
		FullMethod: fullMethod,
		Req:        req,
	}

	result, err := m.authPolicyEngine.Eval(ctx, input)
	if err != nil {
		return ctx, false, err
	}

	ctx, allow, err := reconcileResult(ctx, result, m.entryFetcher, m.agentAuthorizer)
	if err != nil {
		return ctx, false, err
	}

	return ctx, allow, nil
}

func reconcileResult(ctx context.Context, res authpolicy.Result, entryFetcher EntryFetcher, agentAuthorizer AgentAuthorizer) (context.Context, bool, error) {
	// Check things in order of cost
	if res.Allow {
		return ctx, true, nil
	}

	// Check local
	if res.AllowIfLocal && rpccontext.CallerIsLocal(ctx) {
		return ctx, true, nil
	}

	// Get entries
	if res.AllowIfAdmin || res.AllowIfDownstream {
		ctx, entries, err := WithCallerEntries(ctx, entryFetcher)
		if err != nil {
			return ctx, false, err
		}

		if res.AllowIfAdmin {
			if ctx, ok := isAdmin(ctx, entries); ok {
				return ctx, true, nil
			}
		}

		if res.AllowIfDownstream {
			if ctx, ok := isDownstream(ctx, entries); ok {
				return ctx, true, nil
			}
		}
	}

	if res.AllowIfAgent && !rpccontext.CallerIsLocal(ctx) {
		ctx, isAgent, err := isAgent(ctx, agentAuthorizer)
		if err != nil {
			return ctx, false, err
		}

		if isAgent {
			return ctx, true, nil
		}
	}

	return ctx, false, nil
}

func isAdmin(ctx context.Context, entries []*types.Entry) (context.Context, bool) {
	adminEntries := make([]*types.Entry, 0, len(entries))
	for _, entry := range entries {
		if entry.Admin {
			adminEntries = append(adminEntries, entry)
		}
	}

	if len(adminEntries) == 0 {
		return ctx, false
	}
	return rpccontext.WithCallerAdminEntries(ctx, adminEntries), true
}

func isDownstream(ctx context.Context, entries []*types.Entry) (context.Context, bool) {
	downstreamEntries := make([]*types.Entry, 0, len(entries))
	for _, entry := range entries {
		if entry.Downstream {
			downstreamEntries = append(downstreamEntries, entry)
		}
	}

	if len(downstreamEntries) == 0 {
		return ctx, false
	}
	return rpccontext.WithCallerDownstreamEntries(ctx, downstreamEntries), true
}

func isAgent(ctx context.Context, agentAuthorizer AgentAuthorizer) (context.Context, bool, error) {
	agentSVID, ok := rpccontext.CallerX509SVID(ctx)
	if !ok {
		return ctx, false, status.Error(codes.PermissionDenied, "caller does not have an X509-SVID")
	}

	agentID, ok := rpccontext.CallerID(ctx)
	if !ok {
		return ctx, false, status.Error(codes.PermissionDenied, "caller does not have a SPIFFE ID")
	}

	if err := agentAuthorizer.AuthorizeAgent(ctx, agentID, agentSVID); err != nil {
		if status.Convert(err).Code() != codes.PermissionDenied {
			return ctx, false, err
		}
		return ctx, false, nil
	}

	return rpccontext.WithAgentCaller(ctx), true, nil
}
