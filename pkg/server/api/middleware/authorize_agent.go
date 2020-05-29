package middleware

import (
	"context"
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AgentAuthorizer interface {
	// AuthorizeAgent authorizes the agent indicated by the given ID and SVID.
	//
	// It returns PERMISSION_DENIED if the agent is not authorized.
	AuthorizeAgent(ctx context.Context, agentID spiffeid.ID, agentSVID *x509.Certificate) error
}

type AgentAuthorizerFunc func(ctx context.Context, agentID spiffeid.ID, agentSVID *x509.Certificate) error

func (fn AgentAuthorizerFunc) AuthorizeAgent(ctx context.Context, agentID spiffeid.ID, agentSVID *x509.Certificate) error {
	return fn(ctx, agentID, agentSVID)
}

func AuthorizeAgent(authorizer AgentAuthorizer) Authorizer {
	return agentAuthorizer{authorizer: authorizer}
}

type agentAuthorizer struct {
	authorizer AgentAuthorizer
}

func (a agentAuthorizer) Name() string {
	return "agent"
}

func (a agentAuthorizer) AuthorizeCaller(ctx context.Context) (context.Context, error) {
	agentID, ok := rpccontext.CallerID(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "caller does not have a SPIFFE ID")
	}

	agentSVID, ok := rpccontext.CallerX509SVID(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "caller does not have an X509-SVID")
	}

	if err := a.authorizer.AuthorizeAgent(ctx, agentID, agentSVID); err != nil {
		return nil, err
	}

	return rpccontext.WithAgentCaller(ctx), nil
}
