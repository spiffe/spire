package endpoints

import (
	"context"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/api/rpccontext"
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
		middleware.Preprocess(addWatcherPIDToLogger),
		middleware.Preprocess(verifySecurityHeader),
	)
}

func addWatcherPIDToLogger(ctx context.Context, fullMethod string) (context.Context, error) {
	watcher, ok := peertracker.WatcherFromContext(ctx)
	if ok {
		ctx = rpccontext.WithLogger(ctx, rpccontext.Logger(ctx).WithField(telemetry.PID, watcher.PID()))
	}
	return ctx, nil
}

func verifySecurityHeader(ctx context.Context, fullMethod string) (context.Context, error) {
	if isWorkloadAPIMethod(fullMethod) && !hasSecurityHeader(ctx) {
		return nil, status.Errorf(codes.InvalidArgument, "security header missing from request")
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
