package endpoints

import (
	"context"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	workloadAPIMethodPrefix = "/SpiffeWorkloadAPI/"
)

func Middleware(log logrus.FieldLogger, metrics telemetry.Metrics) middleware.Middleware {
	return middleware.Chain(
		middleware.WithLogger(log),
		middleware.WithMetrics(metrics),
		withPerServiceConnectionMetrics(metrics),
		middleware.Preprocess(addWatcherPID),
		middleware.Preprocess(verifySecurityHeader),
		middleware.Postprocess(discardAgentCallMetrics),
	)
}

func addWatcherPID(ctx context.Context, _ string, _ any) (context.Context, error) {
	watcher, ok := peertracker.WatcherFromContext(ctx)
	if ok {
		pid := int(watcher.PID())
		ctx = rpccontext.WithLogger(ctx, rpccontext.Logger(ctx).WithField(telemetry.PID, pid))
		ctx = rpccontext.WithCallerPID(ctx, pid)
	}
	return ctx, nil
}

func verifySecurityHeader(ctx context.Context, fullMethod string, _ any) (context.Context, error) {
	if isWorkloadAPIMethod(fullMethod) && !hasSecurityHeader(ctx) {
		return nil, status.Error(codes.InvalidArgument, "security header missing from request")
	}
	return ctx, nil
}

func isWorkloadAPIMethod(fullMethod string) bool {
	return strings.HasPrefix(fullMethod, workloadAPIMethodPrefix)
}

func hasSecurityHeader(ctx context.Context) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	return ok && len(md["workload.spiffe.io"]) == 1 && md["workload.spiffe.io"][0] == "true"
}

// discardAgentCallMetrics prevents RPC metrics from being emitted for calls
// made by the agent itself (e.g. health check loopback calls to the Workload
// API). This runs in Postprocess before the metrics middleware finalizes the
// call counter, so discarding here prevents the counter from emitting.
func discardAgentCallMetrics(ctx context.Context, _ string, _ bool, _ error) {
	watcher, ok := peertracker.WatcherFromContext(ctx)
	if ok && int(watcher.PID()) == os.Getpid() {
		if counter, ok := rpccontext.CallCounter(ctx).(*telemetry.CallCounter); ok {
			counter.Discard()
		}
	}
}
