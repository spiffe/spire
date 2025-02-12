package sqlstore

import (
	"database/sql"
	"errors"

	_ "gitee.com/opengauss/openGauss-connector-go-pq"
	"github.com/jinzhu/gorm"
	"github.com/lib/pq"
)

type gaussDB struct{}

func (g gaussDB) connect(cfg *configuration, isReadOnly bool) (db *gorm.DB, version string, supportsCTE bool, err error) {
	if cfg.databaseTypeConfig == nil {
		return nil, "", false, errors.New("missing datastore configuration")
	}

	connString := getConnectionString(cfg, isReadOnly)
	dbSQL, errSqlOpen := sql.Open("opengauss", connString)
	if errSqlOpen != nil {
		return nil, "", false, errSqlOpen
	}

	db, errOpen := gorm.Open("postgres", dbSQL)
	if errOpen != nil {
		return nil, "", false, errOpen
	}

	version, err = queryVersion(db, "SHOW server_version")
	if err != nil {
		return nil, "", false, err
	}

	return db, version, true, nil
}

func (g gaussDB) isConstraintViolation(err error) bool {
	var e *pq.Error
	ok := errors.As(err, &e)
	// "23xxx" is the constraint violation class for PostgreSQL, and the same is true for GaussDB
	return ok && e.Code.Class() == "23"
}
