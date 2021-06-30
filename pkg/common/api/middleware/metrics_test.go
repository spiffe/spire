package middleware_test

import (
	"context"
	"testing"

	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/api/rpccontext"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestWithMetrics(t *testing.T) {
	for _, tt := range []struct {
		name             string
		rpcErr           error
		withExtraLabel   bool
		statusLabelValue string
	}{
		{
			name:             "success",
			rpcErr:           nil,
			withExtraLabel:   false,
			statusLabelValue: codes.OK.String(),
		},
		{
			name:             "success with label",
			rpcErr:           nil,
			withExtraLabel:   true,
			statusLabelValue: codes.OK.String(),
		},
		{
			name:             "failure",
			rpcErr:           status.Error(codes.PermissionDenied, "ohno"),
			withExtraLabel:   false,
			statusLabelValue: codes.PermissionDenied.String(),
		},
		{
			name:             "failure with label",
			rpcErr:           status.Error(codes.PermissionDenied, "ohno"),
			withExtraLabel:   true,
			statusLabelValue: codes.PermissionDenied.String(),
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var expectedLabels []telemetry.Label

			metrics := fakemetrics.New()
			m := middleware.WithMetrics(metrics)
			ctx, err := m.Preprocess(context.Background(), fakeFullMethod, nil)
			if tt.withExtraLabel {
				rpccontext.AddMetricsLabel(ctx, "NAME", "VALUE")
				expectedLabels = append(expectedLabels, telemetry.Label{Name: "NAME", Value: "VALUE"})
			}
			require.NoError(t, err)
			m.Postprocess(ctx, fakeFullMethod, false, tt.rpcErr)

			expectedLabels = append(expectedLabels, telemetry.Label{Name: "status", Value: tt.statusLabelValue})

			assert.Equal(t, []fakemetrics.MetricItem{
				{
					Type:   fakemetrics.IncrCounterWithLabelsType,
					Key:    []string{"rpc", "foo", "v1", "foo", "some_method"},
					Val:    1.00,
					Labels: expectedLabels,
				},
				{
					Type:   fakemetrics.MeasureSinceWithLabelsType,
					Key:    []string{"rpc", "foo", "v1", "foo", "some_method", "elapsed_time"},
					Val:    0.00, // This is the elapsed time on the call counter, which doesn't currently support injecting a clock.
					Labels: expectedLabels,
				},
			}, metrics.AllMetrics())
		})
	}
}
