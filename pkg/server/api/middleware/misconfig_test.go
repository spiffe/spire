package middleware

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/test/spiretest"
)

func TestLogMisconfiguration(t *testing.T) {
	mockClk, done := setupClock(t)
	defer done()

	log, hook := test.NewNullLogger()

	baseCtx := context.Background()
	baseCtx = rpccontext.WithLogger(baseCtx, log)
	ctx1 := rpccontext.WithNames(baseCtx, api.Names{Service: "service", Method: "method1"})
	ctx2 := rpccontext.WithNames(baseCtx, api.Names{Service: "service", Method: "method2"})

	// Log various messages from various method contexts and make sure no
	// repeated messages are logged.
	logMisconfiguration(ctx1, "message1a")
	logMisconfiguration(ctx1, "message1a")
	logMisconfiguration(ctx1, "message1a")
	logMisconfiguration(ctx1, "message1b")
	logMisconfiguration(ctx1, "message1b")
	logMisconfiguration(ctx1, "message1b")
	logMisconfiguration(ctx2, "message2a")
	logMisconfiguration(ctx2, "message2a")
	logMisconfiguration(ctx2, "message2a")
	logMisconfiguration(ctx2, "message2b")
	logMisconfiguration(ctx2, "message2b")
	logMisconfiguration(ctx2, "message2b")
	spiretest.AssertLogs(t, hook.AllEntries(), []spiretest.LogEntry{
		{Level: logrus.ErrorLevel, Message: "message1a"},
		{Level: logrus.ErrorLevel, Message: "message1b"},
		{Level: logrus.ErrorLevel, Message: "message2a"},
		{Level: logrus.ErrorLevel, Message: "message2b"},
	})

	// Now advance the clock and ensure that the messages are logged again
	hook.Reset()
	mockClk.Add(misconfigLogEvery)
	logMisconfiguration(ctx1, "message1a")
	logMisconfiguration(ctx1, "message1b")
	logMisconfiguration(ctx2, "message2a")
	logMisconfiguration(ctx2, "message2b")
	spiretest.AssertLogs(t, hook.AllEntries(), []spiretest.LogEntry{
		{Level: logrus.ErrorLevel, Message: "message1a"},
		{Level: logrus.ErrorLevel, Message: "message1b"},
		{Level: logrus.ErrorLevel, Message: "message2a"},
		{Level: logrus.ErrorLevel, Message: "message2b"},
	})
}
