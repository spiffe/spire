package sqlstore

import (
	"context"

	"github.com/jinzhu/gorm"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
)

type dialect interface {
	connect(ctx context.Context, cfg *sqlcommon.Configuration, isReadOnly bool) (db *gorm.DB, version string, supportsCTE bool, err error)
	isConstraintViolation(err error) bool
}
