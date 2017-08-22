package node

import (
	"context"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/spiffe/sri/control_plane/api/node/proto"
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

func (mw LoggingMiddleware) FetchBaseSVID(ctx context.Context, request sri_proto.FetchBaseSVIDRequest) (response sri_proto.FetchBaseSVIDResponse) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "FetchBaseSVID",
			"request", request.String(),
			"took", time.Since(begin),
		)
	}(time.Now())

	response = mw.next.FetchBaseSVID(ctx, request)
	return
}

func (mw LoggingMiddleware) FetchSVID(ctx context.Context, request sri_proto.FetchSVIDRequest) (response sri_proto.FetchSVIDResponse) {
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

func (mw LoggingMiddleware) FetchCPBundle(ctx context.Context, request sri_proto.FetchCPBundleRequest) (response sri_proto.FetchCPBundleResponse) {
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

func (mw LoggingMiddleware) FetchFederatedBundle(ctx context.Context, request sri_proto.FetchFederatedBundleRequest) (response sri_proto.FetchFederatedBundleResponse) {
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
