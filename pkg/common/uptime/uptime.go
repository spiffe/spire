package uptime

import (
	"context"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// by default, report every 10 seconds.
const _defaultReportInterval = time.Second * 10

var start = time.Now()

func Uptime() time.Duration {
	return time.Since(start)
}

var getUptimeFunc = func() float32 {
	return float32(Uptime() / time.Millisecond)
}

func reportMetrics(ctx context.Context, t *clock.Ticker, m telemetry.Metrics) {
	defer t.Stop()
	for {
		telemetry.EmitUptime(m, getUptimeFunc())
		select {
		case <-t.C:
		case <-ctx.Done():
			return
		}
	}
}

func ReportMetrics(ctx context.Context, reportInterval time.Duration, metrics telemetry.Metrics) {
	if reportInterval.Milliseconds() <= 0 {
		reportInterval = _defaultReportInterval
	}
	go reportMetrics(ctx, clock.New().Ticker(reportInterval), metrics)
}
