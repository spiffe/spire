package endpoints

import (
	"context"
	"sync/atomic"

	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/telemetry"
	sdsAPITelemetry "github.com/spiffe/spire/pkg/common/telemetry/agent"
	"github.com/spiffe/spire/pkg/common/telemetry/agent/adminapi"
	workloadAPITelemetry "github.com/spiffe/spire/pkg/common/telemetry/agent/workloadapi"
)

func withPerServiceConnectionMetrics(metrics telemetry.Metrics) middleware.Middleware {
	return &connectionMetrics{
		metrics: metrics,
	}
}

type connectionMetrics struct {
	metrics                   telemetry.Metrics
	workloadAPIConns          int32
	sdsAPIConns               int32
	delegatedIdentityAPIConns int32
}

func (m *connectionMetrics) Preprocess(ctx context.Context, _ string, _ any) (context.Context, error) {
	if names, ok := rpccontext.Names(ctx); ok {
		switch names.RawService {
		case middleware.WorkloadAPIServiceName:
			workloadAPITelemetry.IncrConnectionCounter(m.metrics)
			workloadAPITelemetry.SetConnectionTotalGauge(m.metrics, atomic.AddInt32(&m.workloadAPIConns, 1))
		case middleware.EnvoySDSv3ServiceName:
			sdsAPITelemetry.IncrSDSAPIConnectionCounter(m.metrics)
			sdsAPITelemetry.SetSDSAPIConnectionTotalGauge(m.metrics, atomic.AddInt32(&m.sdsAPIConns, 1))
		case middleware.DelegatedIdentityServiceName:
			adminapi.IncrDelegatedIdentityAPIConnectionCounter(m.metrics)
			adminapi.SetDelegatedIdentityAPIConnectionGauge(m.metrics, atomic.AddInt32(&m.delegatedIdentityAPIConns, 1))
		case middleware.HealthServiceName, middleware.ServerReflectionServiceName, middleware.ServerReflectionV1AlphaServiceName:
			// Intentionally not emitting metrics for health and reflection services
		default:
			middleware.LogMisconfiguration(ctx, "unrecognized service for connection metrics: "+names.Service)
		}
	}
	return ctx, nil
}

func (m *connectionMetrics) Postprocess(ctx context.Context, _ string, _ bool, _ error) {
	if names, ok := rpccontext.Names(ctx); ok {
		switch names.RawService {
		case middleware.WorkloadAPIServiceName:
			workloadAPITelemetry.SetConnectionTotalGauge(m.metrics, atomic.AddInt32(&m.workloadAPIConns, -1))
		case middleware.EnvoySDSv3ServiceName:
			sdsAPITelemetry.SetSDSAPIConnectionTotalGauge(m.metrics, atomic.AddInt32(&m.sdsAPIConns, -1))
		case middleware.DelegatedIdentityServiceName:
			adminapi.SetDelegatedIdentityAPIConnectionGauge(m.metrics, atomic.AddInt32(&m.delegatedIdentityAPIConns, -1))
		case middleware.HealthServiceName, middleware.ServerReflectionServiceName, middleware.ServerReflectionV1AlphaServiceName:
			// Intentionally not emitting metrics for health and reflection services
		default:
			middleware.LogMisconfiguration(ctx, "unrecognized service for connection metrics: "+names.Service)
		}
	}
}
