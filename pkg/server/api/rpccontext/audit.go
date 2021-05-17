package rpccontext

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api/audit"
)

type auditLogKey struct{}

func WithAuditLog(ctx context.Context, auditLog audit.Log) context.Context {
	return context.WithValue(ctx, auditLogKey{}, auditLog)
}

func AddRPCAuditFields(ctx context.Context, fields logrus.Fields) {
	auditLog := AuditLog(ctx)
	auditLog.AddFields(fields)
}

func EmitRPCAudit(ctx context.Context, fields logrus.Fields) {
	AuditLog(ctx).Emit(fields)
}

func EmitRPCAuditError(ctx context.Context, err error) {
	AuditLog(ctx).EmitError(err)
}

func EmitBatchRPCAudit(ctx context.Context, s *types.Status, fields logrus.Fields) {
	AuditLog(ctx).EmitBatch(s, fields)
}

func AuditLog(ctx context.Context) audit.Log {
	auditLog, ok := ctx.Value(auditLogKey{}).(audit.Log)
	if ok {
		return auditLog
	}

	panic("RPC context missing audit log")
}
