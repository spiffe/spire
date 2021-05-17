package middleware

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/server/api/audit"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
)

func WithAuditLog() Middleware {
	return auditLogMiddleware{}
}

type auditLogMiddleware struct {
	Middleware
}

func (m auditLogMiddleware) Preprocess(ctx context.Context, fullMethod string) (context.Context, error) {
	log := rpccontext.Logger(ctx)

	if fields := fieldsFromContext(ctx); len(fields) > 0 {
		log = log.WithFields(fields)
	}

	auditLog := audit.New(log)

	ctx = rpccontext.WithAuditLog(ctx, auditLog)

	return ctx, nil
}

func (m auditLogMiddleware) Postprocess(ctx context.Context, fullMethod string, handlerInvoked bool, rpcErr error) {
	if rpcErr != nil {
		rpccontext.AuditLog(ctx).EmitError(rpcErr)
	}
}

// fieldsFromContext get caller fields from context
func fieldsFromContext(ctx context.Context) logrus.Fields {
	fields := logrus.Fields{}
	callerInfo, ok := peertracker.CallerFromContext(ctx)
	if !ok {
		return fields
	}

	if callerInfo.UID != 0 {
		fields["caller-uid"] = callerInfo.UID
	}
	if callerInfo.GID != 0 {
		fields["caller-gid"] = callerInfo.GID
	}

	// path to binary
	if callerInfo.BinaryAddr != "" {
		fields["caller-path"] = callerInfo.BinaryAddr
	}

	return fields
}
