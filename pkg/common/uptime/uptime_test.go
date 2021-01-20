package uptime

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/assert"
)

func TestReportMetrics(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	for _, tt := range []struct {
		name            string
		reportInterval  time.Duration
		testUpTime      time.Duration
		expectedMetrics []fakemetrics.MetricItem
	}{
		{
			name:           "report uptime metrics with 10 milliseconds interval",
			reportInterval: 10 * time.Millisecond,
			testUpTime:     200 * time.Millisecond,
			expectedMetrics: []fakemetrics.MetricItem{
				{Type: fakemetrics.SetGaugeType, Key: []string{"uptime_in_ms"}, Val: 200},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			metrics := fakemetrics.New()
			// overwrite the variable to use mock clock.
			clk = clock.NewMock(t)
			start = clk.Now().Add(-tt.testUpTime)
			reportMetrics(ctx, 0*time.Nanosecond, metrics)
			assert.Equal(t, tt.expectedMetrics, metrics.AllMetrics())
		})
	}
}
