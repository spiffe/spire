package sqlcommon

import (
	"errors"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lib/pq"
)

// IsPostgresConstraintViolation reports whether err is a PostgreSQL
// constraint violation (SQLSTATE class 23). It matches errors from both
// lib/pq and pgx, since connections may be opened through either driver.
func IsPostgresConstraintViolation(err error) bool {
	if pqErr, ok := errors.AsType[*pq.Error](err); ok {
		return pqErr.Code.Class() == "23"
	}
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		return strings.HasPrefix(pgErr.Code, "23")
	}
	return false
}

func IsMySQLConstraintViolation(err error) bool {
	var e *mysql.MySQLError
	ok := errors.As(err, &e)
	return ok && e.Number == 1062 // ER_DUP_ENTRY
}
