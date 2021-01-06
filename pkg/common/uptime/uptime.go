package uptime

import (
	"context"
	"time"

	"github.com/spiffe/spire/pkg/common/telemetry"
)

// by default, report every 10 seconds.
const _defaultReportInterval = time.Second * 10

var start = time.Now()

func Uptime() time.Duration {
	return time.Since(start)
}

func ReportMetrics(ctx context.Context, reportInterval time.Duration, metrics telemetry.Metrics) {
	if len(reportInterval.String()) == 0 {
		reportInterval = _defaultReportInterval
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(reportInterval):
				telemetry.EmitUptime(metrics, float32(Uptime()/time.Millisecond))
			}
		}
	}()
}
