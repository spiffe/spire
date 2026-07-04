//go:build !cgo

package sqlstore

import (
	"context"
	"errors"

	"github.com/jinzhu/gorm"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
)

type sqliteDB struct {
	log logrus.FieldLogger
}

func (s sqliteDB) connect(ctx context.Context, cfg *sqlcommon.Configuration, isReadOnly bool) (db *gorm.DB, version string, supportsCTE bool, err error) {
	return nil, "", false, errors.New("sqlite3 is not a supported dialect when CGO is not enabled")
}

func (s sqliteDB) isConstraintViolation(err error) bool {
	return sqlcommon.IsSQLiteConstraintViolation(err)
}
