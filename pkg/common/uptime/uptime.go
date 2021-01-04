package uptime

import (
	"context"
	"github.com/andres-erbsen/clock"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"time"
)

var start = time.Now()

func Uptime() time.Duration {
	return time.Since(start)
}

func ReportMetrics(ctx context.Context, reportInterval time.Duration, metrics telemetry.Metrics) error {
	clk := clock.New()
	startTime := clk.Now()

	if len(reportInterval.String()) == 0 {
		// by default, report every 10 seconds.
		reportInterval = time.Second * 10
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-clk.After(reportInterval):
				telemetry.EmitUptime(metrics, float32(clk.Now().Sub(startTime)/time.Millisecond))
			}
		}
	}()

	return nil
}
