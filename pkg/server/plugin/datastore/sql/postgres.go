package sql

import (
	"github.com/jinzhu/gorm"
	// gorm postgres dialect init registration
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

type postgres struct{}

func (p postgres) connect(cfg *configuration, connectionString string) (*gorm.DB, error) {
	db, err := gorm.Open("postgres", connectionString)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}
	return db, nil

}
