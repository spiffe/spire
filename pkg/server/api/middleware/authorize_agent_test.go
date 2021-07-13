package middleware_test

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAgentAuthorizerName(t *testing.T) {
	assert.Equal(t, "agent", middleware.AuthorizeAgent(nil).Name())
}

func TestAgentAuthorizer(t *testing.T) {
	agentSVID := &x509.Certificate{}

	agentID := spiffeid.Must("example.org", "agent")
	otherID := spiffeid.Must("example.org", "other")

	authorizer := middleware.AuthorizeAgent(middleware.AgentAuthorizerFunc(
		func(ctx context.Context, actualID spiffeid.ID, actualSVID *x509.Certificate) error {
			// Make sure that the passed in SVID matches that provided on the
			// context.
			if agentSVID != actualSVID {
				return status.Error(codes.Internal, "X509-SVID was not passed into authorizer")
			}

			if actualID != agentID {
				return status.Error(codes.PermissionDenied, "caller is not an active agent")
			}

			return nil
		},
	))

	t.Run("an agent", func(t *testing.T) {
		ctxIn := context.Background()
		ctxIn = rpccontext.WithCallerID(ctxIn, agentID)
		ctxIn = rpccontext.WithCallerX509SVID(ctxIn, agentSVID)

		ctxOut, err := authorizer.AuthorizeCaller(ctxIn)
		require.NoError(t, err)
		assert.True(t, rpccontext.CallerIsAgent(ctxOut))
	})

	t.Run("not an agent", func(t *testing.T) {
		ctxIn := context.Background()
		ctxIn = rpccontext.WithCallerID(ctxIn, otherID)
		ctxIn = rpccontext.WithCallerX509SVID(ctxIn, agentSVID)

		ctxOut, err := authorizer.AuthorizeCaller(ctxIn)
		spiretest.RequireGRPCStatus(t, err, codes.PermissionDenied, "caller is not an active agent")
		assert.Nil(t, ctxOut)
	})

	t.Run("caller has no ID", func(t *testing.T) {
		ctxIn := context.Background()
		ctxIn = rpccontext.WithCallerX509SVID(ctxIn, agentSVID)

		ctxOut, err := authorizer.AuthorizeCaller(ctxIn)
		spiretest.RequireGRPCStatus(t, err, codes.PermissionDenied, "caller does not have a SPIFFE ID")
		assert.Nil(t, ctxOut)
	})

	t.Run("caller has no X509SVID", func(t *testing.T) {
		ctxIn := context.Background()
		ctxIn = rpccontext.WithCallerID(ctxIn, agentID)

		ctxOut, err := authorizer.AuthorizeCaller(ctxIn)
		spiretest.RequireGRPCStatus(t, err, codes.PermissionDenied, "caller does not have an X509-SVID")
		assert.Nil(t, ctxOut)
	})
}
