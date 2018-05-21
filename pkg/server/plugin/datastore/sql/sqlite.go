package sql

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

type sqlite struct{}

func (s sqlite) connect(connectionString string) (*gorm.DB, error) {
	path := connectionString
	if path == ":memory:" {
		path = path + "?cache=shared"
	}
	path = "file:" + path

	db, err := gorm.Open("sqlite3", connectionString)
	if err != nil {
		return nil, err
	}
	db.Exec("PRAGMA foreign_keys = ON")

	return db, nil
}
