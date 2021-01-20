package uptime

import (
	"context"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// Report every 10 seconds.
const reportInterval = time.Second * 10

var (
	clk   = clock.New()
	start = clk.Now()
)

func Uptime() time.Duration {
	return clk.Now().Sub(start)
}

func reportMetrics(ctx context.Context, interval time.Duration, m telemetry.Metrics) {
	t := clk.Ticker(interval)
	defer t.Stop()
	for {
		telemetry.EmitUptime(m, float32(Uptime()/time.Millisecond))
		select {
		case <-t.C:
		case <-ctx.Done():
			return
		}
	}
}

func ReportMetrics(ctx context.Context, metrics telemetry.Metrics) {
	go reportMetrics(ctx, reportInterval, metrics)
}
