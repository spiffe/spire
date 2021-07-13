package middleware_test

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	authorizerA = makeAuthorizer("A", codes.OK)
	authorizerB = makeAuthorizer("B", codes.PermissionDenied)
	authorizerC = makeAuthorizer("C", codes.Internal)
)

func TestAnyOfAuthorizerName(t *testing.T) {
	authorizer := middleware.AuthorizeAnyOf(authorizerA, authorizerB)
	require.Equal(t, "any-of[A,B]", authorizer.Name())
}

func TestAnyOfAuthorizer(t *testing.T) {
	for _, tt := range []struct {
		name            string
		authorizers     []middleware.Authorizer
		expectCode      codes.Code
		expectMsg       string
		expectLogs      []spiretest.LogEntry
		expectWrapCount int
	}{
		{
			name:       "no authorizers",
			expectCode: codes.Internal,
			expectMsg:  "authorization misconfigured (no authorizers)",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Authorization misconfigured (no authorizers); this is a bug",
				},
			},
		},
		{
			name:            "codes OK and OK",
			authorizers:     []middleware.Authorizer{authorizerA, authorizerA},
			expectCode:      codes.OK,
			expectWrapCount: 3, // 1 initial + two from authorizerA
		},
		{
			name:            "codes OK and PERMISSION_DENIED",
			authorizers:     []middleware.Authorizer{authorizerA, authorizerB},
			expectCode:      codes.OK,
			expectWrapCount: 2, // 1 initial + one from authorizerA
		},
		{
			name:        "codes PERMISSION_DENIED and PERMISSION_DENIED",
			authorizers: []middleware.Authorizer{authorizerB, authorizerB},
			expectCode:  codes.PermissionDenied,
			expectMsg:   `caller must be one of ["B" "B"]`,
		},
		{
			name:        "codes OK and INTERNAL",
			authorizers: []middleware.Authorizer{authorizerA, authorizerC},
			expectCode:  codes.Internal,
			expectMsg:   "Internal",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Create a new context with a logger and a wrap count of one. The
			// wrap count will help us detect, in a round about way, that the
			// context was passed through to the authorizers.
			log, hook := test.NewNullLogger()
			ctxIn := rpccontext.WithLogger(context.Background(), log)
			ctxIn = wrapContext(ctxIn)

			authorizer := middleware.AuthorizeAnyOf(tt.authorizers...)
			ctxOut, err := authorizer.AuthorizeCaller(ctxIn)
			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			spiretest.AssertLogs(t, hook.AllEntries(), tt.expectLogs)
			if tt.expectCode == codes.OK {
				assert.Equal(t, tt.expectWrapCount, wrapCount(ctxOut))
			} else {
				assert.Nil(t, ctxOut)
			}
		})
	}
}

func makeAuthorizer(name string, code codes.Code) middleware.Authorizer {
	return fakeAuthorizer{
		name: name,
		code: code,
	}
}

type fakeAuthorizer struct {
	name string
	code codes.Code
}

func (a fakeAuthorizer) Name() string {
	return a.name
}

func (a fakeAuthorizer) AuthorizeCaller(ctx context.Context) (context.Context, error) {
	if a.code == codes.OK {
		return wrapContext(ctx), nil
	}
	return nil, status.Error(a.code, a.code.String())
}
