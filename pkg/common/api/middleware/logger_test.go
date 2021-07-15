package middleware_test

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/api/rpccontext"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
)

func TestWithLogger(t *testing.T) {
	log, hook := test.NewNullLogger()
	m := middleware.WithLogger(log)

	ctx, err := m.Preprocess(context.Background(), fakeFullMethod, nil)
	assert.NoError(t, err)
	rpccontext.Logger(ctx).Info("HELLO")

	// Assert the log contents
	spiretest.AssertLogs(t, hook.AllEntries(), []spiretest.LogEntry{
		{
			Level:   logrus.InfoLevel,
			Message: "HELLO",
			Data: logrus.Fields{
				"service": "foo.v1.Foo",
				"method":  "SomeMethod",
			},
		},
	})

	// Assert that we can call Postprocess without it panicking. That's as
	// close as we can test the noop implementation for the logging middleware.
	assert.NotPanics(t, func() {
		m.Postprocess(context.Background(), fakeFullMethod, false, nil)
	})
}
