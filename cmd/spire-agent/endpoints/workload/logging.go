package workload

import (
	"context"
	"time"

	"github.com/go-kit/kit/log"
	pb "github.com/spiffe/sri/pkg/api/workload"
	"github.com/spiffe/sri/pkg/common"
)

type ServerServiceMiddleWare func(Service) Service

func SelectorServiceLoggingMiddleWare(logger log.Logger) ServerServiceMiddleWare {
	return func(next Service) Service {
		return LoggingMiddleware{logger, next}
	}
}

type LoggingMiddleware struct {
	logger log.Logger
	next   Service
}

func (mw LoggingMiddleware) FetchBundles(ctx context.Context, request pb.SpiffeId) (response pb.Bundles, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "FetchBundles",
			"request", request.String(),
			"took", time.Since(begin),
		)
	}(time.Now())

	response, err = mw.next.FetchBundles(ctx, request)
	return
}

func (mw LoggingMiddleware) FetchAllBundles(ctx context.Context, request common.Empty) (response pb.Bundles, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "FetchAllBundles",
			"request", request.String(),
			"took", time.Since(begin),
		)
	}(time.Now())

	response, err = mw.next.FetchAllBundles(ctx, request)
	return
}
