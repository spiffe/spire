package sqlstore

import (
	"errors"

	"github.com/jinzhu/gorm"
	"github.com/lib/pq"

	// gorm postgres dialect init registration
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

type postgresDB struct{}

func (p postgresDB) connect(cfg *configuration, isReadOnly bool) (db *gorm.DB, version string, supportsCTE bool, err error) {
	db, err = gorm.Open("postgres", getConnectionString(cfg, isReadOnly))
	if err != nil {
		return nil, "", false, sqlError.Wrap(err)
	}

	version, err = queryVersion(db, "SHOW server_version")
	if err != nil {
		return nil, "", false, err
	}

	// Supported versions of PostgreSQL all support CTE so unconditionally
	// return true.
	return db, version, true, nil
}

func (p postgresDB) isConstraintViolation(err error) bool {
	var e *pq.Error
	ok := errors.As(err, &e)
	// "23xxx" is the constraint violation class for PostgreSQL
	return ok && e.Code.Class() == "23"
}
