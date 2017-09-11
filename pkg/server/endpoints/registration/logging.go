package registration

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	pb "github.com/spiffe/spire/pkg/api/registration"
	"github.com/spiffe/spire/pkg/common"
)

type RegistrationServiceMiddleWare func(RegistrationService) RegistrationService

func ServiceLoggingMiddleWare(logger logrus.FieldLogger) RegistrationServiceMiddleWare {
	return func(next RegistrationService) RegistrationService {
		return LoggingMiddleware{logger, next}
	}
}

type LoggingMiddleware struct {
	log  logrus.FieldLogger
	next RegistrationService
}

func (mw LoggingMiddleware) CreateEntry(ctx context.Context, request common.RegistrationEntry) (response pb.RegistrationEntryID, err error) {
	defer func(begin time.Time) {
		fields := logrus.Fields{
			"method":  "CreateEntry",
			"request": request.String(),
			"error":   err,
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("New registration entry created")
	}(time.Now())

	response, err = mw.next.CreateEntry(ctx, request)
	return
}

func (mw LoggingMiddleware) DeleteEntry(ctx context.Context, request pb.RegistrationEntryID) (response common.RegistrationEntry, err error) {
	defer func(begin time.Time) {
		fields := logrus.Fields{
			"method":  "DeleteEntry",
			"request": request.String(),
			"error":   err,
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("Registration entry deleted")
	}(time.Now())

	response, err = mw.next.DeleteEntry(ctx, request)
	return
}

func (mw LoggingMiddleware) FetchEntry(ctx context.Context, request pb.RegistrationEntryID) (response common.RegistrationEntry, err error) {
	defer func(begin time.Time) {
		fields := logrus.Fields{
			"method":  "FetchEntry",
			"request": request.String(),
			"error":   err,
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("Registration entry retrieved")
	}(time.Now())

	response, err = mw.next.FetchEntry(ctx, request)
	return
}

func (mw LoggingMiddleware) UpdateEntry(ctx context.Context, request pb.UpdateEntryRequest) (response common.RegistrationEntry, err error) {
	defer func(begin time.Time) {
		fields := logrus.Fields{
			"method":  "UpdateEntry",
			"request": request.String(),
			"error":   err,
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("Registration entry updated")
	}(time.Now())

	response, err = mw.next.UpdateEntry(ctx, request)
	return
}

func (mw LoggingMiddleware) ListByParentID(ctx context.Context, request pb.ParentID) (response common.RegistrationEntries, err error) {
	defer func(begin time.Time) {
		fields := logrus.Fields{
			"method":  "ListByParentID",
			"request": request.String(),
			"error":   err,
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("Registration entries retrieved")
	}(time.Now())

	response, err = mw.next.ListByParentID(ctx, request)
	return
}

func (mw LoggingMiddleware) ListBySelector(ctx context.Context, request common.Selector) (response common.RegistrationEntries, err error) {
	defer func(begin time.Time) {
		fields := logrus.Fields{
			"method":  "ListBySelector",
			"request": request.String(),
			"error":   err,
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("Registration entries retrieved")
	}(time.Now())

	response, err = mw.next.ListBySelector(ctx, request)
	return
}

func (mw LoggingMiddleware) ListBySpiffeID(ctx context.Context, request pb.SpiffeID) (response common.RegistrationEntries, err error) {
	defer func(begin time.Time) {
		fields := logrus.Fields{
			"method":  "ListBySpiffeID",
			"request": request.String(),
			"error":   err,
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("Registration entries retrieved")
	}(time.Now())

	response, err = mw.next.ListBySpiffeID(ctx, request)
	return
}

func (mw LoggingMiddleware) CreateFederatedBundle(ctx context.Context, request pb.CreateFederatedBundleRequest) (response common.Empty, err error) {
	defer func(begin time.Time) {
		fields := logrus.Fields{
			"method":  "CreateFederatedBundle",
			"request": request.String(),
			"error":   err,
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("Created new federated bundle")
	}(time.Now())

	response, err = mw.next.CreateFederatedBundle(ctx, request)
	return
}

func (mw LoggingMiddleware) ListFederatedBundles(ctx context.Context, request common.Empty) (response pb.ListFederatedBundlesReply, err error) {
	defer func(begin time.Time) {
		fields := logrus.Fields{
			"method":  "ListFederatedBundles",
			"request": request.String(),
			"error":   err,
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("Federated bundles retrieved")
	}(time.Now())

	response, err = mw.next.ListFederatedBundles(ctx, request)
	return
}

func (mw LoggingMiddleware) UpdateFederatedBundle(ctx context.Context, request pb.FederatedBundle) (response common.Empty, err error) {
	defer func(begin time.Time) {
		fields := logrus.Fields{
			"method":  "UpdateFederatedBundle",
			"request": request.String(),
			"error":   err,
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("Federated bundle updated")
	}(time.Now())

	response, err = mw.next.UpdateFederatedBundle(ctx, request)
	return
}

func (mw LoggingMiddleware) DeleteFederatedBundle(ctx context.Context, request pb.FederatedSpiffeID) (response common.Empty, err error) {
	defer func(begin time.Time) {
		fields := logrus.Fields{
			"method":  "DeleteFederatedBundle",
			"request": request.String(),
			"error":   err,
			"took":    time.Since(begin),
		}
		mw.log.WithFields(fields).Debug("Federated bundle deleted")
	}(time.Now())

	response, err = mw.next.DeleteFederatedBundle(ctx, request)
	return
}
