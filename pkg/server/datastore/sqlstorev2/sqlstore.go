package sqlstorev2

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// PluginName is the catalog name of the GORM v2 SQL datastore.
const PluginName = "sql_v2"

// Plugin is a SQL datastore backed by GORM v2. It holds a read-write
// connection and, when ro_connection_string is set, a read-only one.
type Plugin struct {
	log logrus.FieldLogger

	mu   sync.Mutex
	db   *sqlDB
	roDb *sqlDB
}

type sqlDB struct {
	*gorm.DB
	raw              *sql.DB
	databaseType     string
	connectionString string
	supportsCTE      bool
	dialect          dialect
}

// New returns an unconfigured Plugin. Configure must be called before use.
func New(log logrus.FieldLogger) *Plugin {
	return &Plugin{log: log}
}

// Close closes the read-write and read-only connections if open. It is safe
// to call multiple times.
func (ds *Plugin) Close() error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	var errs error
	if ds.db != nil {
		errs = errors.Join(errs, ds.db.raw.Close())
		ds.db = nil
	}
	if ds.roDb != nil {
		errs = errors.Join(errs, ds.roDb.raw.Close())
		ds.roDb = nil
	}
	return errs
}

// RawScan runs a raw query on the read-write connection and scans the result
// into dest. It holds ds.mu for the whole query so a concurrent Configure or
// Close cannot swap or close the connection mid-scan. It is intended for
// tests, so blocking a reconfigure for the duration is acceptable.
func (ds *Plugin) RawScan(dest any, query string) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if ds.db == nil {
		return sqlcommon.NewSQLError("datastore is not configured")
	}
	return ds.db.Raw(query).Scan(dest).Error
}

// Configure parses the HCL config, validates it, and opens the connection(s).
func (ds *Plugin) Configure(ctx context.Context, hclConfiguration string) error {
	config, err := sqlcommon.BuildConfig(hclConfiguration)
	if err != nil {
		return err
	}
	if err := sqlcommon.ConfigValidate(config); err != nil {
		return err
	}
	return ds.openConnections(ctx, config)
}

func (ds *Plugin) openConnections(ctx context.Context, config *sqlcommon.Configuration) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if err := ds.openConnection(ctx, config, false); err != nil {
		return err
	}
	if config.RoConnectionString == "" {
		if ds.roDb != nil {
			err := ds.roDb.raw.Close()
			ds.roDb = nil
			if err != nil {
				return sqlcommon.NewWrappedSQLError(err)
			}
		}
		return nil
	}
	return ds.openConnection(ctx, config, true)
}

func (ds *Plugin) openConnection(ctx context.Context, config *sqlcommon.Configuration, isReadOnly bool) error {
	connectionString := sqlcommon.GetConnectionString(config, isReadOnly)

	current := ds.db
	if isReadOnly {
		current = ds.roDb
	}

	// Keep the existing connection when neither the connection string nor
	// the database type changed, but still apply the current log_sql setting.
	if current != nil && current.connectionString == connectionString &&
		current.databaseType == config.DBTypeConfig.DatabaseType {
		current.DB = withSQLLogging(current.DB, config.LogSQL, ds.log)
		return nil
	}

	var connMaxLifetime time.Duration
	if config.ConnMaxLifetime != nil {
		d, err := time.ParseDuration(*config.ConnMaxLifetime)
		if err != nil {
			return fmt.Errorf("failed to parse conn_max_lifetime %q: %w", *config.ConnMaxLifetime, err)
		}
		connMaxLifetime = d
	}

	dia, err := ds.newDialect(config.DBTypeConfig.DatabaseType)
	if err != nil {
		return err
	}

	gdb, version, supportsCTE, err := dia.connect(ctx, config, isReadOnly)
	if err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}

	raw, err := gdb.DB()
	if err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}

	const maxOpenConns = 100
	raw.SetMaxOpenConns(maxOpenConns)
	if config.MaxOpenConns != nil {
		raw.SetMaxOpenConns(*config.MaxOpenConns)
	}
	const maxIdleConns = 100
	raw.SetMaxIdleConns(maxIdleConns)
	if config.MaxIdleConns != nil {
		raw.SetMaxIdleConns(*config.MaxIdleConns)
	}
	const connMaxIdleTime = time.Second * 30
	raw.SetConnMaxIdleTime(connMaxIdleTime)
	if config.ConnMaxLifetime != nil {
		raw.SetConnMaxLifetime(connMaxLifetime)
	}

	newDB := &sqlDB{
		DB:               withSQLLogging(gdb, config.LogSQL, ds.log),
		raw:              raw,
		databaseType:     config.DBTypeConfig.DatabaseType,
		dialect:          dia,
		connectionString: connectionString,
		supportsCTE:      supportsCTE,
	}

	if current != nil {
		current.raw.Close()
	}

	if isReadOnly {
		ds.roDb = newDB
	} else {
		ds.db = newDB
	}
	ds.log.WithFields(logrus.Fields{
		telemetry.Type:     config.DBTypeConfig.DatabaseType,
		telemetry.Version:  version,
		telemetry.ReadOnly: isReadOnly,
	}).Info("Connected to SQL database")
	return nil
}

func (ds *Plugin) newDialect(databaseType string) (dialect, error) {
	switch {
	case sqlcommon.IsSQLiteDbType(databaseType):
		return sqliteDB{log: ds.log}, nil
	case sqlcommon.IsPostgresDbType(databaseType):
		return postgresDB{}, nil
	case sqlcommon.IsMySQLDbType(databaseType):
		return mysqlDB{log: ds.log}, nil
	default:
		return nil, sqlcommon.NewSQLError("unsupported database_type: %s", databaseType)
	}
}

// gormConfig is the config every dialect opens its connection with. SQL
// logging starts disabled so the connection probes run during connect are
// not logged; withSQLLogging applies log_sql once the connection is set up.
func gormConfig() *gorm.Config {
	return &gorm.Config{Logger: gormlogger.Discard}
}

// withSQLLogging returns a handle on db's connection pool that logs SQL
// statements through log, with a subsystem_name=gorm field, when logSQL is
// true, and discards them otherwise.
func withSQLLogging(db *gorm.DB, logSQL bool, log logrus.FieldLogger) *gorm.DB {
	lg := gormlogger.Discard
	if logSQL {
		lg = newLogrusGormLogger(log.WithField(telemetry.SubsystemName, "gorm"))
	}
	return db.Session(&gorm.Session{NewDB: true, Logger: lg})
}

// closeOnError closes db's connection pool and returns err joined with any
// error from closing. Dialects call it when connect fails after the pool is
// open.
func closeOnError(db *gorm.DB, err error) error {
	raw, rawErr := db.DB()
	if rawErr != nil {
		return errors.Join(err, rawErr)
	}
	return errors.Join(err, raw.Close())
}

// queryVersion runs the dialect version query on the raw *sql.DB.
func queryVersion(ctx context.Context, db *gorm.DB, query string) (string, error) {
	raw, err := db.DB()
	if err != nil {
		return "", err
	}
	var version string
	if err := raw.QueryRowContext(ctx, query).Scan(&version); err != nil {
		return "", err
	}
	return version, nil
}

// logrusGormLogger implements gorm.io/gorm/logger.Interface on top of logrus.
// SQL statements (Trace) and informational messages are logged at Debug;
// warnings and errors keep their level.
type logrusGormLogger struct {
	log logrus.FieldLogger
}

func newLogrusGormLogger(log logrus.FieldLogger) gormlogger.Interface {
	return logrusGormLogger{log: log}
}

func (l logrusGormLogger) LogMode(gormlogger.LogLevel) gormlogger.Interface { return l }

func (l logrusGormLogger) Info(_ context.Context, msg string, data ...any) {
	l.log.Debugf(msg, data...)
}

func (l logrusGormLogger) Warn(_ context.Context, msg string, data ...any) {
	l.log.Warnf(msg, data...)
}

func (l logrusGormLogger) Error(_ context.Context, msg string, data ...any) {
	l.log.Errorf(msg, data...)
}

func (l logrusGormLogger) Trace(_ context.Context, _ time.Time, fc func() (string, int64), err error) {
	sql, rows := fc()
	entry := l.log.WithField("rows", rows)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		entry.WithError(err).Debug(sql)
		return
	}
	entry.Debug(sql)
}
