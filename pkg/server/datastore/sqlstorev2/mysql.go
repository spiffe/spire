package sqlstorev2

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	gomysql "github.com/go-sql-driver/mysql"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"github.com/spiffe/spire/pkg/server/datastore/sqldriver/awsrds"
	"github.com/spiffe/spire/pkg/server/datastore/sqldriver/azurerds"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type mysqlDB struct {
	log logrus.FieldLogger
}

func (my mysqlDB) connect(ctx context.Context, cfg *sqlcommon.Configuration, isReadOnly bool) (db *gorm.DB, version string, supportsCTE bool, err error) {
	if cfg.DBTypeConfig == nil {
		return nil, "", false, errors.New("missing datastore configuration")
	}

	mysqlConfig, err := sqlcommon.ConfigureMySQLConnection(cfg, isReadOnly)
	if err != nil {
		return nil, "", false, err
	}

	switch {
	case cfg.DBTypeConfig.AWSMySQL != nil:
		dsn, err := sqlcommon.BuildAWSMySQLDSN(cfg, mysqlConfig)
		if err != nil {
			return nil, "", false, err
		}
		db, err = openSQLDriver(awsrds.MySQLDriverName, dsn, newMySQLDialector)
		if err != nil {
			return nil, "", false, err
		}
	case cfg.DBTypeConfig.AzureMySQL != nil:
		dsn, err := sqlcommon.BuildAzureMySQLDSN(cfg, mysqlConfig)
		if err != nil {
			return nil, "", false, err
		}
		db, err = openSQLDriver(azurerds.MySQLDriverName, dsn, newMySQLDialector)
		if err != nil {
			return nil, "", false, err
		}
	default:
		db, err = gorm.Open(mysql.Open(mysqlConfig.FormatDSN()), gormConfig())
		if err != nil {
			return nil, "", false, err
		}
	}

	version, err = queryVersion(ctx, db, sqlcommon.MySQLVersionQuery)
	if err != nil {
		return nil, "", false, closeOnError(db, err)
	}

	if strings.HasPrefix(version, "5.7.") {
		my.log.Warn("MySQL 5.7 is no longer officially supported, and SPIRE does not guarantee compatibility with MySQL 5.7. Consider upgrading to a newer version of MySQL.")
	}

	supportsCTE, err = my.supportsCTE(ctx, db)
	if err != nil {
		return nil, "", false, closeOnError(db, err)
	}
	return db, version, supportsCTE, nil
}

func (my mysqlDB) isConstraintViolation(err error) bool {
	return sqlcommon.IsMySQLConstraintViolation(err)
}

func (my mysqlDB) supportsCTE(ctx context.Context, gormDB *gorm.DB) (bool, error) {
	raw, err := gormDB.DB()
	if err != nil {
		return false, err
	}
	var value int64
	err = raw.QueryRowContext(ctx, "WITH a AS (SELECT 1 AS v) SELECT * FROM a;").Scan(&value)
	switch {
	case err == nil:
		return true, nil
	case my.isParseError(err):
		return false, nil
	default:
		return false, err
	}
}

func (my mysqlDB) isParseError(err error) bool {
	var e *gomysql.MySQLError
	ok := errors.As(err, &e)
	return ok && e.Number == 1064 // ER_PARSE_ERROR
}

func newMySQLDialector(conn *sql.DB) gorm.Dialector {
	return mysql.New(mysql.Config{Conn: conn})
}
