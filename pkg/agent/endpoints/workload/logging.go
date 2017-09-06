package workload

import (
	"context"
	"time"

	"github.com/go-kit/kit/log"
	pb "github.com/spiffe/spire/pkg/api/workload"
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

func (mw LoggingMiddleware) FetchSVIDBundle(ctx context.Context, request pb.FetchSVIDBundleRequest) (response pb.FetchSVIDBundleResponse) {
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

func (mw LoggingMiddleware) FetchSVIDBundles(ctx context.Context, request pb.Empty) (response pb.FetchSVIDBundlesResponse) {
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

func (mw LoggingMiddleware) FetchFederatedBundle(ctx context.Context, request pb.FetchFederatedBundleRequest) (response pb.FetchFederatedBundleResponse) {
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

func (mw LoggingMiddleware) FetchFederatedBundles(ctx context.Context, request pb.Empty) (response pb.FetchFederatedBundlesResponse) {
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
