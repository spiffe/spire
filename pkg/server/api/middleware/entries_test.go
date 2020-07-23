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

func TestWithCallerEntries(t *testing.T) {
	adminID := spiffeid.Must("example.org", "admin")
	adminEntries := []*types.Entry{{Id: "A"}}

	failMeID := spiffeid.Must("example.org", "fail-me")

	entryFetcher := middleware.EntryFetcherFunc(
		func(ctx context.Context, id spiffeid.ID) ([]*types.Entry, error) {
			if id == adminID {
				return adminEntries, nil
			}
			return nil, errors.New("ohno")
		},
	)

	failingFetcher := middleware.EntryFetcherFunc(
		func(ctx context.Context, id spiffeid.ID) ([]*types.Entry, error) {
			return nil, errors.New("should not have been called")
		},
	)

	t.Run("success", func(t *testing.T) {
		ctxIn := rpccontext.WithCallerID(context.Background(), adminID)
		ctxOut1, entries, err := middleware.WithCallerEntries(ctxIn, entryFetcher)
		// Assert that the call succeeds and returns a new context and the entries.
		assert.NotEqual(t, ctxIn, ctxOut1)
		assert.Equal(t, adminEntries, entries)
		assert.NoError(t, err)

		// Now call again and make sure it returns the same context. The failing
		// fetcher is used to ensure it is not called because the context
		// already has the entries.
		ctxOut2, entries, err := middleware.WithCallerEntries(ctxOut1, failingFetcher)
		assert.Equal(t, ctxOut1, ctxOut2)
		assert.Equal(t, adminEntries, entries)
		assert.NoError(t, err)
	})

	t.Run("no caller ID", func(t *testing.T) {
		ctxIn := context.Background()
		ctxOut, entries, err := middleware.WithCallerEntries(ctxIn, entryFetcher)
		// Assert that the call succeeds and returns an unchanged context and no entries.
		assert.Equal(t, ctxIn, ctxOut)
		assert.Nil(t, entries)
		assert.NoError(t, err)
	})

	t.Run("fetch fails", func(t *testing.T) {
		log, hook := test.NewNullLogger()
		ctxIn := rpccontext.WithCallerID(rpccontext.WithLogger(context.Background(), log), failMeID)
		ctxOut, entries, err := middleware.WithCallerEntries(ctxIn, entryFetcher)
		// Assert that the call fails and returns a nil context and no entries.
		assert.Nil(t, ctxOut)
		assert.Nil(t, entries)
		spiretest.AssertGRPCStatus(t, err, codes.Internal, "failed to fetch caller entries: ohno")
		spiretest.AssertLogs(t, hook.AllEntries(), []spiretest.LogEntry{
			{
				Level:   logrus.ErrorLevel,
				Message: "Failed to fetch caller entries",
				Data: logrus.Fields{
					logrus.ErrorKey: "ohno",
				},
			},
		})
	})
}
