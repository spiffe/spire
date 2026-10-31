package sqlstorev2

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newTxTestPlugin(t *testing.T) *Plugin {
	dbPath := sqlitePath(t)
	ds := newSQLitePlugin(t)
	require.NoError(t, ds.Configure(context.Background(), fmt.Sprintf(`
		database_type = "sqlite3"
		connection_string = "%s"
	`, dbPath)))
	return ds
}

func TestWithReadTxRollsBack(t *testing.T) {
	ds := newTxTestPlugin(t)

	err := ds.withReadTx(context.Background(), func(tx *gorm.DB) error {
		return tx.Create(&JoinToken{Token: "t", Expiry: 1}).Error
	})
	require.NoError(t, err)

	var count int
	require.NoError(t, ds.RawScan(&count, "SELECT COUNT(*) FROM join_tokens"))
	require.Zero(t, count)
}

func TestWithWriteTxRollsBackOnError(t *testing.T) {
	ds := newTxTestPlugin(t)

	err := ds.withWriteTx(context.Background(), func(tx *gorm.DB) error {
		if err := tx.Create(&JoinToken{Token: "t", Expiry: 1}).Error; err != nil {
			return err
		}
		return status.Error(codes.FailedPrecondition, "op failed")
	})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	var count int
	require.NoError(t, ds.RawScan(&count, "SELECT COUNT(*) FROM join_tokens"))
	require.Zero(t, count)
}

func TestUseServerTimestampsRoundsToSecond(t *testing.T) {
	dbPath := sqlitePath(t)
	ds := newSQLitePlugin(t)
	ds.SetUseServerTimestamps(true)
	require.NoError(t, ds.Configure(context.Background(), fmt.Sprintf(`
		database_type = "sqlite3"
		connection_string = "%s"
	`, dbPath)))

	require.NoError(t, ds.CreateJoinToken(context.Background(), &datastore.JoinToken{Token: "t", Expiry: time.Now()}))

	var createdAt time.Time
	require.NoError(t, ds.RawScan(&createdAt, "SELECT created_at FROM join_tokens"))
	require.Zero(t, createdAt.Nanosecond())
}

func TestGormToGRPCStatus(t *testing.T) {
	ds := newTxTestPlugin(t)

	requireCode := func(err error, code codes.Code) {
		t.Helper()
		require.Equal(t, code, status.Code(ds.gormToGRPCStatus(err)))
	}

	requireCode(sqlcommon.NewWrappedSQLError(gorm.ErrRecordNotFound), codes.NotFound)
	requireCode(sqlcommon.NewValidationError("bad"), codes.InvalidArgument)
	requireCode(errors.New("boom"), codes.Unknown)

	orig := status.Error(codes.FailedPrecondition, "x")
	require.Equal(t, orig, ds.gormToGRPCStatus(orig))

	insert := func(tx *gorm.DB) error {
		return tx.Create(&JoinToken{Token: "dup", Expiry: 1}).Error
	}
	require.NoError(t, ds.withWriteTx(context.Background(), insert))
	err := ds.withWriteTx(context.Background(), func(tx *gorm.DB) error {
		return sqlcommon.NewWrappedSQLError(insert(tx))
	})
	require.Equal(t, codes.AlreadyExists, status.Code(err))
}

func TestWithReadModifyWriteTxCommits(t *testing.T) {
	ds := newTxTestPlugin(t)

	err := ds.withReadModifyWriteTx(context.Background(), func(tx *gorm.DB) error {
		return tx.Create(&JoinToken{Token: "t", Expiry: 1}).Error
	})
	require.NoError(t, err)

	var count int
	require.NoError(t, ds.RawScan(&count, "SELECT COUNT(*) FROM join_tokens"))
	require.Equal(t, 1, count)
}

func TestForUpdateHandleDoesNotLeakConditions(t *testing.T) {
	ds := newTxTestPlugin(t)

	err := ds.withWriteTx(context.Background(), func(tx *gorm.DB) error {
		for _, token := range []string{"a", "b"} {
			if err := tx.Create(&JoinToken{Token: token, Expiry: 1}).Error; err != nil {
				return err
			}
		}
		locked := forUpdate(tx)
		for _, token := range []string{"a", "b"} {
			var got []JoinToken
			if err := locked.Where("token = ?", token).Find(&got).Error; err != nil {
				return err
			}
			require.Len(t, got, 1)
			require.Equal(t, token, got[0].Token)
		}
		return nil
	})
	require.NoError(t, err)
}

func TestLockForUpdate(t *testing.T) {
	dryRun := &gorm.Config{DryRun: true, DisableAutomaticPing: true}
	open := func(d gorm.Dialector) *gorm.DB {
		db, err := gorm.Open(d, dryRun)
		require.NoError(t, err)
		return db
	}

	tests := []struct {
		dbType string
		dialer gorm.Dialector
		locked bool
	}{
		{sqlcommon.PostgreSQL, postgres.New(postgres.Config{DSN: "host=invalid"}), true},
		{sqlcommon.MySQL, mysql.New(mysql.Config{DSN: "u:p@tcp(invalid)/db", SkipInitializeWithVersion: true}), true},
		{sqlcommon.SQLite, sqlite.Open(":memory:"), false},
	}
	for _, tt := range tests {
		t.Run(tt.dbType, func(t *testing.T) {
			tx := lockForUpdate(tt.dbType, open(tt.dialer))
			// Every query on the handle is locked, not just the first.
			for range 2 {
				sql := tx.Where("trust_domain = ?", "x").Take(&Bundle{}).Statement.SQL.String()
				require.Equal(t, tt.locked, strings.Contains(sql, "FOR UPDATE"), sql)
			}
		})
	}
}
