package sql

import (
	"github.com/jinzhu/gorm"
	// gorm postgres dialect init registration
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

type postgres struct{}

func (p postgres) connect(cfg *configuration) (*gorm.DB, error) {
	db, err := gorm.Open("postgres", cfg.ConnectionString)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}
	return db, nil

}
