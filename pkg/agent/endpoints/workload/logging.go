package workload

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	pb "github.com/spiffe/spire/pkg/api/workload"
)

type ServerServiceMiddleWare func(WorkloadService) WorkloadService

func SelectorServiceLoggingMiddleWare(logger *logrus.Logger) ServerServiceMiddleWare {
	return func(next WorkloadService) WorkloadService {
		return LoggingMiddleware{logger, next}
	}
}

type LoggingMiddleware struct {
	log  *logrus.Logger
	next WorkloadService
}

func (mw LoggingMiddleware) FetchSVIDBundle(ctx context.Context, request pb.FetchSVIDBundleRequest) (response pb.FetchSVIDBundleResponse) {
	defer func(begin time.Time) {
		fields := &logrus.Fields{
			"method":  "FetchSVIDBundle",
			"request": request.String(),
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("SVID requested")
	}(time.Now())

	response = mw.next.FetchSVIDBundle(ctx, request)
	return
}

func (mw LoggingMiddleware) FetchSVIDBundles(ctx context.Context, request pb.Empty) (response pb.FetchSVIDBundlesResponse) {
	defer func(begin time.Time) {
		fields := &logrus.Fields{
			"method":  "FetchSVIDBundles",
			"request": request.String(),
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("SVIDs requested")
	}(time.Now())

	response = mw.next.FetchSVIDBundles(ctx, request)
	return
}

func (mw LoggingMiddleware) FetchFederatedBundle(ctx context.Context, request pb.FetchFederatedBundleRequest) (response pb.FetchFederatedBundleResponse) {
	defer func(begin time.Time) {
		fields := &logrus.Fields{
			"method":  "FetchFederatedBundle",
			"request": request.String(),
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("Federated bundle requested")
	}(time.Now())

	response = mw.next.FetchFederatedBundle(ctx, request)
	return
}

func (mw LoggingMiddleware) FetchFederatedBundles(ctx context.Context, request pb.Empty) (response pb.FetchFederatedBundlesResponse) {
	defer func(begin time.Time) {
		fields := &logrus.Fields{
			"method":  "FetchFederatedBundles",
			"request": request.String(),
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("Federated bundles requested")
	}(time.Now())

	response = mw.next.FetchFederatedBundles(ctx, request)
	return
}
