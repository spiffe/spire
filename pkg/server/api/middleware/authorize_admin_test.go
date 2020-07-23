package middleware_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
)

func TestAdminAuthorizerName(t *testing.T) {
	assert.Equal(t, "admin", middleware.AuthorizeAdmin(nil).Name())
}

func TestAdminAuthorizer(t *testing.T) {
	adminID := spiffeid.Must("example.org", "admin")
	adminEntries := []*types.Entry{
		{Id: "1", Admin: true},
		{Id: "2"},
	}

	nonAdminID := spiffeid.Must("example.org", "non-admin")
	nonAdminEntries := []*types.Entry{
		{Id: "3"},
	}

	failMeID := spiffeid.Must("example.org", "fail-me")

	authorizer := middleware.AuthorizeAdmin(middleware.EntryFetcherFunc(
		func(ctx context.Context, id spiffeid.ID) ([]*types.Entry, error) {
			switch id {
			case adminID:
				return adminEntries, nil
			case nonAdminID:
				return nonAdminEntries, nil
			default:
				return nil, errors.New("ohno")
			}
		},
	))

	for _, tt := range []struct {
		name          string
		id            spiffeid.ID
		expectCode    codes.Code
		expectMsg     string
		expectEntries []*types.Entry
		expectLogs    []spiretest.LogEntry
	}{
		{
			name:       "with admin ID",
			id:         adminID,
			expectCode: codes.OK,
			expectEntries: []*types.Entry{
				{Id: "1", Admin: true},
			},
		},
		{
			name:       "with non-admin ID",
			id:         nonAdminID,
			expectCode: codes.PermissionDenied,
			expectMsg:  "caller is not an admin workload",
		},
		{
			name:       "fail to fetch entries",
			id:         failMeID,
			expectCode: codes.Internal,
			expectMsg:  "failed to fetch caller entries: ohno",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to fetch caller entries",
					Data: logrus.Fields{
						logrus.ErrorKey: "ohno",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			log, hook := test.NewNullLogger()
			ctx := rpccontext.WithLogger(context.Background(), log)
			ctx = rpccontext.WithCallerID(ctx, tt.id)

			ctx, err := authorizer.AuthorizeCaller(ctx)
			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			spiretest.AssertLogs(t, hook.AllEntries(), tt.expectLogs)
			if tt.expectCode == codes.OK {
				entries, ok := rpccontext.CallerAdminEntries(ctx)
				if assert.True(t, ok, "context should have admin entries") {
					assert.Equal(t, tt.expectEntries, entries, "admin entries don't match")
				}
			} else {
				assert.Nil(t, ctx)
			}
		})
	}
}
