package middleware

import (
	"context"

	"github.com/pkg/errors"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/policy"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (m *authorizationMiddleware) opaAuth(ctx context.Context, req interface{}, fullMethod string) (allow bool, err error) {
	if m.policyEngine == nil {
		return false, errors.New("No policy engine object found")
	}

	var (
		spiffeID string
	)
	// Get SPIFFE ID
	id, ok := rpccontext.CallerID(ctx)
	if ok {
		spiffeID = id.String()
	}

	input := policy.Input{
		Caller:     spiffeID,
		FullMethod: fullMethod,
		Req:        req,
	}

	result, err := m.policyEngine.Eval(ctx, input)
	if err != nil {
		return false, err
	}

	allow, err = reconcileResult(ctx, result, m.entryFetcher, m.agentAuthorizer)
	if err != nil {
		return false, err
	}

	return allow, nil
}

func reconcileResult(ctx context.Context, res policy.Result, entryFetcher EntryFetcher, agentAuthorizer AgentAuthorizer) (allow bool, err error) {
	// Check things in order of cost
	if res.Allow {
		return true, nil
	}

	// Check local
	if res.AllowIfLocal && rpccontext.CallerIsLocal(ctx) {
		return true, nil
	}

	// Get entries
	if res.AllowIfAdmin || res.AllowIfDownstream {
		_, entries, err := WithCallerEntries(ctx, entryFetcher)
		if err != nil {
			return false, err
		}

		if res.AllowIfAdmin && isAdmin(entries) {
			return true, nil
		}

		if res.AllowIfDownstream && isDownstream(entries) {
			return true, nil
		}
	}

	if res.AllowIfAgent {
		isAgent, err := isAgent(ctx, agentAuthorizer)
		if err == nil && isAgent {
			return true, nil
		}
	}

	return false, nil
}

func isAdmin(entries []*types.Entry) bool {
	adminEntries := make([]*types.Entry, 0, len(entries))
	for _, entry := range entries {
		if entry.Admin {
			adminEntries = append(adminEntries, entry)
		}
	}
	return len(adminEntries) != 0
}

func isDownstream(entries []*types.Entry) bool {
	downstreamEntries := make([]*types.Entry, 0, len(entries))
	for _, entry := range entries {
		if entry.Downstream {
			downstreamEntries = append(downstreamEntries, entry)
		}
	}
	return len(downstreamEntries) != 0
}

func isAgent(ctx context.Context, agentAuthorizer AgentAuthorizer) (bool, error) {
	agentSVID, ok := rpccontext.CallerX509SVID(ctx)
	if !ok {
		return false, status.Error(codes.PermissionDenied, "caller does not have an X509-SVID")
	}

	agentID, ok := rpccontext.CallerID(ctx)
	if !ok {
		return false, status.Error(codes.PermissionDenied, "caller does not have a SPIFFE ID")
	}

	err := agentAuthorizer.AuthorizeAgent(ctx, agentID, agentSVID)

	return err == nil, nil
}
