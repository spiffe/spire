package rpccontext

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api/audit"
)

type auditLogKey struct{}

func WithAuditLog(ctx context.Context, auditLog audit.Logger) context.Context {
	return context.WithValue(ctx, auditLogKey{}, auditLog)
}

func AddRPCAuditFields(ctx context.Context, fields logrus.Fields) {
	if auditLog, ok := AuditLog(ctx); ok {
		auditLog.AddFields(fields)
	}
}

func AuditRPC(ctx context.Context) {
	if auditLog, ok := AuditLog(ctx); ok {
		auditLog.Audit()
	}
}

func AuditRPCWithFields(ctx context.Context, fields logrus.Fields) {
	if auditLog, ok := AuditLog(ctx); ok {
		auditLog.AuditWithFields(fields)
	}
}

func AuditRPCWithError(ctx context.Context, err error) {
	if auditLog, ok := AuditLog(ctx); ok {
		auditLog.AuditWithError(err)
	}
}

func AuditRPCWithTypesStatus(ctx context.Context, s *types.Status, fieldsFunc func() logrus.Fields) {
	if auditLog, ok := AuditLog(ctx); ok {
		auditLog.AuditWithTypesStatus(fieldsFunc(), s)
	}
}

func AuditLog(ctx context.Context) (audit.Logger, bool) {
	auditLog, ok := ctx.Value(auditLogKey{}).(audit.Logger)
	return auditLog, ok
}
