package sqlstore

import (
	"context"

	"github.com/jinzhu/gorm"
)

type dialect interface {
	connect(ctx context.Context, cfg *configuration, isReadOnly bool) (db *gorm.DB, version string, supportsCTE bool, err error)
	isConstraintViolation(err error) bool
}
