package sql

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

type sqlite struct{}

func (s sqlite) connect(connectionString string) (*gorm.DB, error) {
	db, err := gorm.Open("sqlite3", connectionString)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}
	if err := db.Exec("PRAGMA journal_mode = WAL").Error; err != nil {
		db.Close()
		return nil, sqlError.Wrap(err)
	}
	if err := db.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
		db.Close()
		return nil, sqlError.Wrap(err)
	}

	return db, nil
}
