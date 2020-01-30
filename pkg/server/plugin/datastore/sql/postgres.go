package sql

import (
	"github.com/jinzhu/gorm"
	// gorm postgres dialect init registration
	_ "github.com/jinzhu/gorm/dialects/postgres"
	_ "github.com/spiffe/spire/pkg/server/plugin/datastore"
)

type postgres struct{}

func (p postgres) connect(cfg *configuration, isReadOnlyConnection bool) (*gorm.DB, error) {
	db, err := gorm.Open("postgres", getConnectionString(cfg, isReadOnlyConnection))
	if err != nil {
		return nil, sqlError.Wrap(err)
	}
	return db, nil
}
