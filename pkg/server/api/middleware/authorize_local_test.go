package middleware_test

import (
	"context"
	"testing"

	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestLocalAuthorizerName(t *testing.T) {
	authorizer := middleware.AuthorizeLocal()
	require.Equal(t, "local", authorizer.Name())
}

func TestLocalAuthorizer(t *testing.T) {
	authorizer := middleware.AuthorizeLocal()

	t.Run("caller is local", func(t *testing.T) {
		ctxIn := rpccontext.WithLocalCaller(context.Background())
		ctxOut, err := authorizer.AuthorizeCaller(ctxIn)
		require.NoError(t, err)
		require.Equal(t, ctxIn, ctxOut)
	})

	t.Run("caller is not local", func(t *testing.T) {
		ctxIn := context.Background()
		ctxOut, err := authorizer.AuthorizeCaller(ctxIn)
		spiretest.RequireGRPCStatus(t, err, codes.PermissionDenied, "caller is not local")
		assert.Nil(t, ctxOut)
	})
}
