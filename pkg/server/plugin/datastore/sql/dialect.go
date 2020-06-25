package sql

import "github.com/jinzhu/gorm"

type dialect interface {
	connect(cfg *configuration, isReadOnly bool) (db *gorm.DB, version string, supportsCTE bool, err error)
	isConstraintViolation(err error) bool
}
