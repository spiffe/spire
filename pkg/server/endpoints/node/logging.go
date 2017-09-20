package node

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/spiffe/spire/proto/api/node"
)

type NodeServiceMiddleWare func(Service) Service

func ServiceLoggingMiddleWare(logger logrus.FieldLogger) NodeServiceMiddleWare {
	return func(next Service) Service {
		return LoggingMiddleware{logger, next}
	}
}

type LoggingMiddleware struct {
	log  logrus.FieldLogger
	next Service
}

func (mw LoggingMiddleware) FetchBaseSVID(ctx context.Context, request node.FetchBaseSVIDRequest) (response node.FetchBaseSVIDResponse, err error) {
	defer func(begin time.Time) {
		fields := logrus.Fields{
			"method":  "FetchBaseSVID",
			"request": request.String(),
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("Base SVID Requested")
	}(time.Now())

	response, err = mw.next.FetchBaseSVID(ctx, request)
	return
}

func (mw LoggingMiddleware) FetchSVID(ctx context.Context, request node.FetchSVIDRequest) (response node.FetchSVIDResponse, err error) {
	defer func(begin time.Time) {
		fields := logrus.Fields{
			"method":  "FetchSVID",
			"request": request.String(),
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("SVIDs requested")
	}(time.Now())

	response, err = mw.next.FetchSVID(ctx, request)
	return
}

func (mw LoggingMiddleware) FetchCPBundle(ctx context.Context, request node.FetchCPBundleRequest) (response node.FetchCPBundleResponse, err error) {
	defer func(begin time.Time) {
		fields := logrus.Fields{
			"method":  "FetchCPBundle",
			"request": request.String(),
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("Retrieved SPIRE server bundle")
	}(time.Now())

	response, err = mw.next.FetchCPBundle(ctx, request)
	return
}

func (mw LoggingMiddleware) FetchFederatedBundle(ctx context.Context, request node.FetchFederatedBundleRequest) (response node.FetchFederatedBundleResponse, err error) {
	defer func(begin time.Time) {
		fields := logrus.Fields{
			"method":  "FetchFederatedBundle",
			"request": request.String(),
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("Retrieved federated bundle")
	}(time.Now())

	response, err = mw.next.FetchFederatedBundle(ctx, request)
	return
}
