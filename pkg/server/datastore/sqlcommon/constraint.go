package sqlcommon

import (
	"errors"

	"github.com/go-sql-driver/mysql"
	"github.com/lib/pq"
)

func IsPostgresConstraintViolation(err error) bool {
	var e *pq.Error
	ok := errors.As(err, &e)
	// "23xxx" is the constraint violation class for PostgreSQL
	return ok && e.Code.Class() == "23"
}

func IsMySQLConstraintViolation(err error) bool {
	var e *mysql.MySQLError
	ok := errors.As(err, &e)
	return ok && e.Number == 1062 // ER_DUP_ENTRY
}
