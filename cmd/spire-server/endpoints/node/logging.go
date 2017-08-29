package node

import (
	"context"
	"time"

	"github.com/go-kit/kit/log"
	pb "github.com/spiffe/sri/pkg/api/node"
)

type NodeServiceMiddleWare func(NodeService) NodeService

func SelectorServiceLoggingMiddleWare(logger log.Logger) NodeServiceMiddleWare {
	return func(next NodeService) NodeService {
		return LoggingMiddleware{logger, next}
	}
}

type LoggingMiddleware struct {
	logger log.Logger
	next   NodeService
}

func (mw LoggingMiddleware) FetchBaseSVID(ctx context.Context, request pb.FetchBaseSVIDRequest) (response pb.FetchBaseSVIDResponse, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "FetchBaseSVID",
			"request", request.String(),
			"took", time.Since(begin),
		)
	}(time.Now())

	response, err = mw.next.FetchBaseSVID(ctx, request)
	return
}

func (mw LoggingMiddleware) FetchSVID(ctx context.Context, request pb.FetchSVIDRequest) (response pb.FetchSVIDResponse) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "FetchSVID",
			"request", request.String(),
			"took", time.Since(begin),
		)
	}(time.Now())

	response = mw.next.FetchSVID(ctx, request)
	return
}

func (mw LoggingMiddleware) FetchCPBundle(ctx context.Context, request pb.FetchCPBundleRequest) (response pb.FetchCPBundleResponse) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "FetchCPBundle",
			"request", request.String(),
			"took", time.Since(begin),
		)
	}(time.Now())

	response = mw.next.FetchCPBundle(ctx, request)
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
