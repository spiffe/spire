package uptime

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/test/clock"
	mocktelemetry "github.com/spiffe/spire/test/mock/common/telemetry"
)

func TestReportMetrics(t *testing.T) {
	const _testUptime = 200
	metrics := mocktelemetry.NewMockMetrics(gomock.NewController(t))
	ctx, cancel := context.WithCancel(context.Background())
	metrics.EXPECT().SetGauge([]string{"uptime_in_ms"}, float32(_testUptime)).Do(func(_, _ interface{}) {
		// The expected update cancels the context which causes reportMetrics to return
		cancel()
	})

	// overwrite the variable to use mock clock.
	clk = clock.NewMock(t)
	start = clk.Now().Add(-_testUptime*time.Millisecond)
	reportMetrics(ctx, time.Nanosecond, metrics)
}

