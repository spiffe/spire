package sql

import (
	"errors"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"

	// gorm mysql dialect init registration
	_ "github.com/jinzhu/gorm/dialects/mysql"
)

type mysql struct{}

func (my mysql) connect(connectionString string) (*gorm.DB, error) {
	db, err := gorm.Open("mysql", connectionString)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func validateMySQLConfig(cfg *configuration) error {
	opts, err := mysqldriver.ParseDSN(cfg.ConnectionString)
	if err != nil {
		return sqlError.Wrap(err)
	}

	if !opts.ParseTime {
		return sqlError.Wrap(errors.New("invalid mysql config: missing parseTime=true param in connection_string"))
	}

	return nil
}
