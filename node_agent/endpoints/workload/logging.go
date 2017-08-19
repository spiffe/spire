package workload

import (
"context"
"time"

"github.com/go-kit/kit/log"
node_agent_proto "github.com/spiffe/sri/node_agent/api/workload/pb"
)


type ServerServiceMiddleWare func(WorkloadService) WorkloadService

func SelectorServiceLoggingMiddleWare(logger log.Logger) ServerServiceMiddleWare {
	return func(next WorkloadService) WorkloadService {
		return LoggingMiddleware{logger, next}
	}
}

type LoggingMiddleware struct {
	logger log.Logger
	next   WorkloadService
}

func (mw LoggingMiddleware) FetchSVIDBundle(ctx context.Context, request node_agent_proto.FetchSVIDBundleRequest) (response node_agent_proto.FetchSVIDBundleResponse) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "FetchSVIDBundle",
			"request", request.String(),
			"took", time.Since(begin),
		)
	}(time.Now())

	response = mw.next.FetchSVIDBundle(ctx, request)
	return
}

func (mw LoggingMiddleware) FetchSVIDBundles(ctx context.Context, request node_agent_proto.Empty) (response node_agent_proto.FetchSVIDBundlesResponse) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "FetchSVIDBundles",
			"request", request.String(),
			"took", time.Since(begin),
		)
	}(time.Now())

	response = mw.next.FetchSVIDBundles(ctx, request)
	return
}



func (mw LoggingMiddleware) FetchFederatedBundle(ctx context.Context, request node_agent_proto.FetchFederatedBundleRequest) (response node_agent_proto.FetchFederatedBundleResponse) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "FetchFederatedBundle",
			"request", request.String(),
			"took", time.Since(begin),
		)
	}(time.Now())

	response = mw.next.FetchFederatedBundle(ctx, request)
	return
}


func (mw LoggingMiddleware) FetchFederatedBundles(ctx context.Context, request node_agent_proto.Empty) (response node_agent_proto.FetchFederatedBundlesResponse) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "FetchFederatedBundles",
			"request", request.String(),
			"took", time.Since(begin),
		)
	}(time.Now())

	response = mw.next.FetchFederatedBundles(ctx, request)
	return
}