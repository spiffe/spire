package server

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/plugin"
)

type ServerServiceMiddleWare func(ServerService) ServerService

func SelectorServiceLoggingMiddleWare(logger *logrus.Logger) ServerServiceMiddleWare {
	return func(next ServerService) ServerService {
		return LoggingMiddleware{logger, next}
	}
}

type LoggingMiddleware struct {
	log  *logrus.Logger
	next ServerService
}

func (mw LoggingMiddleware) Stop(ctx context.Context, request sriplugin.StopRequest) (response sriplugin.StopReply, err error) {
	defer func(begin time.Time) {
		fields := &logrus.Fields{
			"method":  "stop",
			"request": request.String(),
			"error":   err,
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("Stopped SPIRE agent")
	}(time.Now())

	response, err = mw.next.Stop(ctx, request)
	return
}

func (mw LoggingMiddleware) PluginInfo(ctx context.Context, request sriplugin.PluginInfoRequest) (response sriplugin.PluginInfoReply, err error) {
	defer func(begin time.Time) {
		fields := &logrus.Fields{
			"method":  "PluginInfo",
			"request": request.String(),
			"error":   err,
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("Retrieved plugin info")
	}(time.Now())

	response, err = mw.next.PluginInfo(ctx, request)
	return
}
