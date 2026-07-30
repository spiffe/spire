package sqlstorev2

import "github.com/spiffe/spire/pkg/server/datastore/sqlcommon"

// newSQLError and newWrappedSQLError are thin aliases so the rest of the
// package reads like v1 while all error construction lives in sqlcommon.
func newSQLError(format string, args ...any) error { return sqlcommon.NewSQLError(format, args...) }
func newWrappedSQLError(err error) error           { return sqlcommon.NewWrappedSQLError(err) }
