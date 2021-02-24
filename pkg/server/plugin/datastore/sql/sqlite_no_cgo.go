// +build !cgo

package sql

import (
	"errors"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/jinzhu/gorm"
)

type sqliteDB struct {
	log hclog.Logger
}

func (s sqliteDB) connect(cfg *configuration, isReadOnly bool) (db *gorm.DB, version string, supportsCTE bool, err error) {
	return nil, "", false, errors.New("sqlite3 is not a supported dialect when CGO is not enabled")
}

func (s sqliteDB) isConstraintViolation(err error) bool {
	return false
}
