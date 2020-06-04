package middleware_test

import (
	"context"
	"testing"

	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/stretchr/testify/require"
)

func TestAnyAuthorizerName(t *testing.T) {
	authorizer := middleware.AuthorizeAny()
	require.Equal(t, "any", authorizer.Name())
}

func TestAnyAuthorizer(t *testing.T) {
	authorizer := middleware.AuthorizeAny()
	ctx, err := authorizer.AuthorizeCaller(context.Background())
	require.NoError(t, err)
	require.Equal(t, ctx, context.Background())
}
