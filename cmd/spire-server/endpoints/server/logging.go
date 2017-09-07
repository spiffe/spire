package server

import (
	"context"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/spiffe/spire/pkg/common/plugin"
)

type ServerServiceMiddleWare func(ServerService) ServerService

func ServiceLoggingMiddleWare(logger log.Logger) ServerServiceMiddleWare {
	return func(next ServerService) ServerService {
		return LoggingMiddleware{logger, next}
	}
}

type LoggingMiddleware struct {
	logger log.Logger
	next   ServerService
}

func (mw LoggingMiddleware) Stop(ctx context.Context, request sriplugin.StopRequest) (response sriplugin.StopReply, err error) {
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

func (mw LoggingMiddleware) PluginInfo(ctx context.Context, request sriplugin.PluginInfoRequest) (response sriplugin.PluginInfoReply, err error) {
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
