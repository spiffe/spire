package sql

import (
	"github.com/jinzhu/gorm"

	// gorm postgres dialect init registration
	_ "github.com/jinzhu/gorm/dialects/postgres"
	_ "github.com/spiffe/spire/pkg/server/plugin/datastore"
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
