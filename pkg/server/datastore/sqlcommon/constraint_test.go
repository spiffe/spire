package sqlcommon

import (
	"errors"
	"fmt"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestIsPostgresConstraintViolation(t *testing.T) {
	for _, tt := range []struct {
		name     string
		err      error
		expected bool
	}{
		{name: "pq unique violation", err: &pq.Error{Code: "23505"}, expected: true},
		{name: "pq other class", err: &pq.Error{Code: "42P01"}},
		{name: "pgx unique violation", err: &pgconn.PgError{Code: "23505"}, expected: true},
		{name: "pgx foreign key violation", err: &pgconn.PgError{Code: "23503"}, expected: true},
		{name: "pgx other class", err: &pgconn.PgError{Code: "42P01"}},
		{name: "wrapped pgx unique violation", err: fmt.Errorf("insert: %w", &pgconn.PgError{Code: "23505"}), expected: true},
		{name: "unrelated error", err: errors.New("oops")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, IsPostgresConstraintViolation(tt.err))
		})
	}
}

func TestIsMySQLConstraintViolation(t *testing.T) {
	require.True(t, IsMySQLConstraintViolation(&mysql.MySQLError{Number: 1062}))
	require.False(t, IsMySQLConstraintViolation(&mysql.MySQLError{Number: 1064}))
	require.False(t, IsMySQLConstraintViolation(errors.New("oops")))
}
