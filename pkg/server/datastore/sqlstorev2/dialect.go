package sqlstorev2

import (
	"context"

	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"gorm.io/gorm"
)

// dialect abstracts the per-database-engine connection and error
// classification logic. The returned *gorm.DB is a gorm v2 handle.
type dialect interface {
	connect(ctx context.Context, cfg *sqlcommon.Configuration, isReadOnly bool) (
		db *gorm.DB, version string, supportsCTE bool, err error)
	isConstraintViolation(err error) bool
}
