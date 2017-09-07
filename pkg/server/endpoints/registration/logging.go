package registration

import (
	"context"
	"time"

	"github.com/go-kit/kit/log"
	pb "github.com/spiffe/spire/pkg/api/registration"
	"github.com/spiffe/spire/pkg/common"
)

type RegistrationServiceMiddleWare func(RegistrationService) RegistrationService

func ServiceLoggingMiddleWare(logger log.Logger) RegistrationServiceMiddleWare {
	return func(next RegistrationService) RegistrationService {
		return LoggingMiddleware{logger, next}
	}
}

type LoggingMiddleware struct {
	logger log.Logger
	next   RegistrationService
}

func (mw LoggingMiddleware) CreateEntry(ctx context.Context, request common.RegistrationEntry) (response pb.RegistrationEntryID, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "CreateEntry",
			"request", request.String(),
			"error", err,
			"took", time.Since(begin),
		)
	}(time.Now())

	response, err = mw.next.CreateEntry(ctx, request)
	return
}

func (mw LoggingMiddleware) DeleteEntry(ctx context.Context, request pb.RegistrationEntryID) (response common.RegistrationEntry, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "DeleteEntry",
			"request", request.String(),
			"error", err,
			"took", time.Since(begin),
		)
	}(time.Now())

	response, err = mw.next.DeleteEntry(ctx, request)
	return
}

func (mw LoggingMiddleware) FetchEntry(ctx context.Context, request pb.RegistrationEntryID) (response common.RegistrationEntry, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "FetchEntry",
			"request", request.String(),
			"error", err,
			"took", time.Since(begin),
		)
	}(time.Now())

	response, err = mw.next.FetchEntry(ctx, request)
	return
}

func (mw LoggingMiddleware) UpdateEntry(ctx context.Context, request pb.UpdateEntryRequest) (response common.RegistrationEntry, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "UpdateEntry",
			"request", request.String(),
			"error", err,
			"took", time.Since(begin),
		)
	}(time.Now())

	response, err = mw.next.UpdateEntry(ctx, request)
	return
}

func (mw LoggingMiddleware) ListByParentID(ctx context.Context, request pb.ParentID) (response common.RegistrationEntries, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "ListByParentID",
			"request", request.String(),
			"error", err,
			"took", time.Since(begin),
		)
	}(time.Now())

	response, err = mw.next.ListByParentID(ctx, request)
	return
}

func (mw LoggingMiddleware) ListBySelector(ctx context.Context, request common.Selector) (response common.RegistrationEntries, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "ListBySelector",
			"request", request.String(),
			"error", err,
			"took", time.Since(begin),
		)
	}(time.Now())

	response, err = mw.next.ListBySelector(ctx, request)
	return
}

func (mw LoggingMiddleware) ListBySpiffeID(ctx context.Context, request pb.SpiffeID) (response common.RegistrationEntries, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "ListBySpiffeID",
			"request", request.String(),
			"error", err,
			"took", time.Since(begin),
		)
	}(time.Now())

	response, err = mw.next.ListBySpiffeID(ctx, request)
	return
}

func (mw LoggingMiddleware) CreateFederatedBundle(ctx context.Context, request pb.CreateFederatedBundleRequest) (response common.Empty, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "CreateFederatedBundle",
			"request", request.String(),
			"error", err,
			"took", time.Since(begin),
		)
	}(time.Now())

	response, err = mw.next.CreateFederatedBundle(ctx, request)
	return
}

func (mw LoggingMiddleware) ListFederatedBundles(ctx context.Context, request common.Empty) (response pb.ListFederatedBundlesReply, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "ListFederatedBundles",
			"request", request.String(),
			"error", err,
			"took", time.Since(begin),
		)
	}(time.Now())

	response, err = mw.next.ListFederatedBundles(ctx, request)
	return
}

func (mw LoggingMiddleware) UpdateFederatedBundle(ctx context.Context, request pb.FederatedBundle) (response common.Empty, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "UpdateFederatedBundle",
			"request", request.String(),
			"error", err,
			"took", time.Since(begin),
		)
	}(time.Now())

	response, err = mw.next.UpdateFederatedBundle(ctx, request)
	return
}

func (mw LoggingMiddleware) DeleteFederatedBundle(ctx context.Context, request pb.FederatedSpiffeID) (response common.Empty, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "DeleteFederatedBundle",
			"request", request.String(),
			"error", err,
			"took", time.Since(begin),
		)
	}(time.Now())

	response, err = mw.next.DeleteFederatedBundle(ctx, request)
	return
}
