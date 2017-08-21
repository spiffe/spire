package server

import (
	"context"
	"time"

	"github.com/go-kit/kit/log"
	node_agent_proto "github.com/spiffe/sri/node_agent/api/server/proto"
)


type ServerServiceMiddleWare func(ServerService) ServerService

func SelectorServiceLoggingMiddleWare(logger log.Logger) ServerServiceMiddleWare {
	return func(next ServerService) ServerService {
		return LoggingMiddleware{logger, next}
	}
}

type LoggingMiddleware struct {
	logger log.Logger
	next   ServerService
}

func (mw LoggingMiddleware) Stop(ctx context.Context, request node_agent_proto.StopRequest) (response node_agent_proto.StopReply, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "Stop",
			"request", request.String(),
			"error", err,
			"took", time.Since(begin),
		)
	}(time.Now())

	response, err = mw.next.Stop(ctx, request)
	return
}

func (mw LoggingMiddleware) PluginInfo(ctx context.Context, request node_agent_proto.PluginInfoRequest) (response node_agent_proto.PluginInfoReply, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "PluginInfo",
			"request", request.String(),
			"error", err,
			"took", time.Since(begin),
		)
	}(time.Now())

	response, err = mw.next.PluginInfo(ctx, request)
	return
}
