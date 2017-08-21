package server

import (
	"context"
	"time"

	"github.com/go-kit/kit/log"
	control_plane_proto "github.com/spiffe/sri/control_plane/api/server/proto"
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

func (mw LoggingMiddleware) Stop(ctx context.Context, request control_plane_proto.StopRequest) (response control_plane_proto.StopReply, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "Stop",
			"selector", request.String(),
			"error", err,
			"took", time.Since(begin),
		)
	}(time.Now())

	response, err = mw.next.Stop(ctx, request)
	return
}

func (mw LoggingMiddleware) PluginInfo(ctx context.Context, request control_plane_proto.PluginInfoRequest) (response control_plane_proto.PluginInfoReply, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "PluginInfo",
			"selector", request.String(),
			"error", err,
			"took", time.Since(begin),
		)
	}(time.Now())

	response, err = mw.next.PluginInfo(ctx, request)
	return
}
