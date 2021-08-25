package middleware

import (
	"context"
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
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
