package middleware

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/api"
	"github.com/spiffe/spire/pkg/common/api/rpccontext"
	"github.com/spiffe/spire/test/clock"
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
	LogMisconfiguration(ctx1, "message1a")
	LogMisconfiguration(ctx1, "message1a")
	LogMisconfiguration(ctx1, "message1a")
	LogMisconfiguration(ctx1, "message1b")
	LogMisconfiguration(ctx1, "message1b")
	LogMisconfiguration(ctx1, "message1b")
	LogMisconfiguration(ctx2, "message2a")
	LogMisconfiguration(ctx2, "message2a")
	LogMisconfiguration(ctx2, "message2a")
	LogMisconfiguration(ctx2, "message2b")
	LogMisconfiguration(ctx2, "message2b")
	LogMisconfiguration(ctx2, "message2b")
	spiretest.AssertLogs(t, hook.AllEntries(), []spiretest.LogEntry{
		{Level: logrus.ErrorLevel, Message: "message1a"},
		{Level: logrus.ErrorLevel, Message: "message1b"},
		{Level: logrus.ErrorLevel, Message: "message2a"},
		{Level: logrus.ErrorLevel, Message: "message2b"},
	})

	// Now advance the clock and ensure that the messages are logged again
	hook.Reset()
	mockClk.Add(misconfigLogEvery)
	LogMisconfiguration(ctx1, "message1a")
	LogMisconfiguration(ctx1, "message1b")
	LogMisconfiguration(ctx2, "message2a")
	LogMisconfiguration(ctx2, "message2b")
	spiretest.AssertLogs(t, hook.AllEntries(), []spiretest.LogEntry{
		{Level: logrus.ErrorLevel, Message: "message1a"},
		{Level: logrus.ErrorLevel, Message: "message1b"},
		{Level: logrus.ErrorLevel, Message: "message2a"},
		{Level: logrus.ErrorLevel, Message: "message2b"},
	})
}

func setupClock(t *testing.T) (*clock.Mock, func()) {
	mockClk := clock.NewMock(t)
	oldClk := misconfigClk
	misconfigClk = mockClk
	return mockClk, func() {
		misconfigClk = oldClk
	}
}
