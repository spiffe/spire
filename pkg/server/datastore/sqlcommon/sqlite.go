//go:build cgo

package sqlcommon

import (
	"errors"

	"github.com/mattn/go-sqlite3"
)

func IsSQLiteConstraintViolation(err error) bool {
	if err == nil {
		return false
	}
	var e sqlite3.Error
	ok := errors.As(err, &e)
	return ok && e.Code == sqlite3.ErrConstraint
}
