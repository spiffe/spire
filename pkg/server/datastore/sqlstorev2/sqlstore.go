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

// PluginName is the catalog name of the gorm v2 datastore. It is not wired
// into the catalog until a later issue.
const PluginName = "sql_v2"

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

func New(log logrus.FieldLogger) *Plugin {
	return &Plugin{log: log}
}

// Close closes the read-write and read-only connections if open. It is safe
// to call multiple times.
func (ds *Plugin) Close() error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	var errs error
	if ds.db != nil && ds.db.raw != nil {
		errs = errors.Join(errs, ds.db.raw.Close())
	}
	if ds.roDb != nil && ds.roDb.raw != nil {
		errs = errors.Join(errs, ds.roDb.raw.Close())
	}
	return errs
}

// RawScan runs a raw query and scans the result into dest. Matches the
// signature of the future sqltest.RawQuerier so the shared suite can consume
// it in a later issue. It guards against being called before a successful
// Configure and takes ds.mu so it does not race a concurrent reconfigure.
func (ds *Plugin) RawScan(dest any, query string) error {
	ds.mu.Lock()
	db := ds.db
	ds.mu.Unlock()
	if db == nil {
		return newSQLError("datastore is not configured")
	}
	return db.Raw(query).Scan(dest).Error
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
	// Reopen only when the connection string changed.
	if current != nil && current.connectionString == connectionString &&
		current.databaseType == config.DBTypeConfig.DatabaseType {
		return nil
	}

	dia, err := ds.newDialect(config.DBTypeConfig.DatabaseType)
	if err != nil {
		return err
	}

	gdb, version, supportsCTE, err := dia.connect(ctx, config, isReadOnly)
	if err != nil {
		return err
	}

	raw, err := gdb.DB()
	if err != nil {
		return newWrappedSQLError(err)
	}

	// Conn-pool options (defaults match v1).
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
		d, err := time.ParseDuration(*config.ConnMaxLifetime)
		if err != nil {
			return fmt.Errorf("failed to parse conn_max_lifetime %q: %w", *config.ConnMaxLifetime, err)
		}
		raw.SetConnMaxLifetime(d)
	}

	newDB := &sqlDB{
		DB:               gdb,
		raw:              raw,
		databaseType:     config.DBTypeConfig.DatabaseType,
		dialect:          dia,
		connectionString: connectionString,
		supportsCTE:      supportsCTE,
	}

	// Close the prior handle if reconfiguring.
	if current != nil && current.raw != nil {
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
	switch databaseType {
	case sqlcommon.SQLite:
		return sqliteDB{log: ds.log}, nil
	case sqlcommon.PostgreSQL, sqlcommon.AWSPostgreSQL:
		return postgresDB{log: ds.log}, nil
	case sqlcommon.MySQL, sqlcommon.AWSMySQL:
		return mysqlDB{log: ds.log}, nil
	default:
		return nil, newSQLError("unsupported database_type: %s", databaseType)
	}
}

// gormConfig builds the gorm v2 config, routing SQL logging through logrus to
// preserve v1's behavior: statements logged via ds.log with a subsystem=gorm
// field, gated by log_sql.
func gormConfig(cfg *sqlcommon.Configuration, log logrus.FieldLogger) *gorm.Config {
	lg := gormlogger.Discard
	if cfg.LogSQL {
		lg = newLogrusGormLogger(log.WithField(telemetry.SubsystemName, "gorm"))
	}
	return &gorm.Config{Logger: lg}
}

// queryVersion runs the dialect version query on the raw *sql.DB.
func queryVersion(ctx context.Context, db *gorm.DB, query string) (string, error) {
	raw, err := db.DB()
	if err != nil {
		return "", newWrappedSQLError(err)
	}
	var version string
	if err := raw.QueryRowContext(ctx, query).Scan(&version); err != nil {
		return "", newWrappedSQLError(err)
	}
	return version, nil
}

// logrusGormLogger implements gorm.io/gorm/logger.Interface, routing gorm's
// SQL output into logrus at Debug level (matching v1's gormLogger.Print).
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
