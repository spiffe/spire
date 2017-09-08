package node

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	pb "github.com/spiffe/spire/pkg/api/node"
)

type NodeServiceMiddleWare func(NodeService) NodeService

func ServiceLoggingMiddleWare(logger *logrus.Logger) NodeServiceMiddleWare {
	return func(next NodeService) NodeService {
		return LoggingMiddleware{logger, next}
	}
}

type LoggingMiddleware struct {
	log  *logrus.Logger
	next NodeService
}

func (mw LoggingMiddleware) FetchBaseSVID(ctx context.Context, request pb.FetchBaseSVIDRequest) (response pb.FetchBaseSVIDResponse, err error) {
	defer func(begin time.Time) {
		fields := &logrus.Fields{
			"method":  "FetchBaseSVID",
			"request": request.String(),
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("Base SVID Requested")
	}(time.Now())

	response, err = mw.next.FetchBaseSVID(ctx, request)
	return
}

func (mw LoggingMiddleware) FetchSVID(ctx context.Context, request pb.FetchSVIDRequest) (response pb.FetchSVIDResponse) {
	defer func(begin time.Time) {
		fields := &logrus.Fields{
			"method":  "FetchSVID",
			"request": request.String(),
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("SVIDs requested")
	}(time.Now())

	response = mw.next.FetchSVID(ctx, request)
	return
}

func (mw LoggingMiddleware) FetchCPBundle(ctx context.Context, request pb.FetchCPBundleRequest) (response pb.FetchCPBundleResponse) {
	defer func(begin time.Time) {
		fields := &logrus.Fields{
			"method":  "FetchCPBundle",
			"request": request.String(),
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("Retrieved SPIRE server bundle")
	}(time.Now())

	response = mw.next.FetchCPBundle(ctx, request)
	return
}

func (mw LoggingMiddleware) FetchFederatedBundle(ctx context.Context, request pb.FetchFederatedBundleRequest) (response pb.FetchFederatedBundleResponse) {
	defer func(begin time.Time) {
		fields := &logrus.Fields{
			"method":  "FetchFederatedBundle",
			"request": request.String(),
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("Retrieved federated bundle")
	}(time.Now())

	response = mw.next.FetchFederatedBundle(ctx, request)
	return
}
