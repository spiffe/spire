package sqlstorev2

import (
	"context"
	"errors"

	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// withReadModifyWriteTx wraps the operation in a transaction appropriate for
// operations that will read one or more rows, change one or more columns in
// those rows, and then set them back. This requires a stronger level of
// consistency that prevents two transactions from doing read-modify-write
// concurrently.
func (ds *Plugin) withReadModifyWriteTx(ctx context.Context, op func(tx *gorm.DB) error) error {
	return ds.withTx(ctx, op, false, true)
}

// lockForUpdate returns a handle that adds `FOR UPDATE` to its queries on
// databases that need it for read-modify-write consistency.
func lockForUpdate(databaseType string, tx *gorm.DB) *gorm.DB {
	switch {
	case sqlcommon.IsMySQLDbType(databaseType):
		// MySQL REPEATABLE READ is weaker than that of PostgreSQL. Namely,
		// PostgreSQL, beyond providing the minimum consistency guarantees
		// mandated for REPEATABLE READ in the standard, automatically fails
		// concurrent transactions that try to update the same target row.
		//
		// To get the same consistency guarantees, have the queries do a
		// `SELECT .. FOR UPDATE` which will implicitly lock queried rows
		// from update by other transactions. This is preferred to a stronger
		// isolation level, like SERIALIZABLE, which is not supported by
		// some MySQL-compatible databases (e.g. Percona XtraDB cluster)
		return forUpdate(tx)
	case sqlcommon.IsPostgresDbType(databaseType):
		// `SELECT .. FOR UPDATE` is also required when PostgreSQL is in
		// hot standby mode for this operation to work properly (see issue #3039).
		return forUpdate(tx)
	default:
		return tx
	}
}

// forUpdate returns a handle that adds `FOR UPDATE` to the queries run on it.
// The session makes each query on the handle start from a fresh statement, so
// conditions from one query do not leak into the next.
func forUpdate(tx *gorm.DB) *gorm.DB {
	return tx.Clauses(clause.Locking{Strength: "UPDATE"}).Session(&gorm.Session{})
}

// withWriteTx wraps the operation in a transaction appropriate for operations
// that unconditionally create/update rows, without reading them first. If two
// transactions try and update at the same time, last writer wins.
func (ds *Plugin) withWriteTx(ctx context.Context, op func(tx *gorm.DB) error) error {
	return ds.withTx(ctx, op, false, false)
}

// withReadTx wraps the operation in a transaction appropriate for operations
// that only read rows.
func (ds *Plugin) withReadTx(ctx context.Context, op func(tx *gorm.DB) error) error {
	return ds.withTx(ctx, op, true, false)
}

func (ds *Plugin) withTx(ctx context.Context, op func(tx *gorm.DB) error, readOnly, lockRows bool) error {
	ds.mu.Lock()
	db := ds.db
	ds.mu.Unlock()
	if db == nil {
		return sqlcommon.NewSQLError("datastore is not configured")
	}

	if db.databaseType == sqlcommon.SQLite && !readOnly {
		// sqlite3 can only have one writer at a time. since we're in WAL mode,
		// there can be concurrent reads and writes, so no lock is necessary
		// over the read operations.
		db.opMu.Lock()
		defer db.opMu.Unlock()
	}

	tx := db.WithContext(ctx).Begin()
	if err := tx.Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}

	opTx := tx
	if lockRows {
		opTx = lockForUpdate(db.databaseType, tx)
	}

	if err := op(opTx); err != nil {
		tx.Rollback()
		return ds.gormToGRPCStatus(err)
	}

	if readOnly {
		// rolling back makes sure that functions that are invoked with
		// withReadTx, and then do writes, will not pass unit tests, since the
		// writes won't be committed.
		return sqlcommon.NewWrappedSQLError(tx.Rollback().Error)
	}
	return sqlcommon.NewWrappedSQLError(tx.Commit().Error)
}

// gormToGRPCStatus takes an error, and converts it to a GRPC error.  If the
// error is already a gRPC status , it will be returned unmodified. Otherwise
// if the error is a gorm error type with a known mapping to a GRPC status,
// that code will be set, otherwise the code will be set to Unknown.
func (ds *Plugin) gormToGRPCStatus(err error) error {
	type grpcStatusError interface {
		error
		GRPCStatus() *status.Status
	}

	if statusError, ok := errors.AsType[grpcStatusError](err); ok {
		return statusError
	}

	code := codes.Unknown
	if _, ok := errors.AsType[*sqlcommon.ValidationError](err); ok {
		code = codes.InvalidArgument
	}

	unwrapped := errors.Unwrap(err)
	switch {
	case errors.Is(unwrapped, gorm.ErrRecordNotFound):
		code = codes.NotFound
	case ds.isConstraintViolation(unwrapped):
		code = codes.AlreadyExists
	default:
	}

	return status.Error(code, err.Error())
}

// isConstraintViolation reports whether err is a unique constraint violation
// for the configured database.
func (ds *Plugin) isConstraintViolation(err error) bool {
	ds.mu.Lock()
	db := ds.db
	ds.mu.Unlock()
	return db != nil && db.dialect.isConstraintViolation(err)
}
