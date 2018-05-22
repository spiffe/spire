package sql

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

type postgres struct{}

func (p postgres) connect(connectionString string) (*gorm.DB, error) {
	db, err := gorm.Open("postgres", connectionString)
	if err != nil {
		return nil, err
	}
	return db, nil

}
