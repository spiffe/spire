package migrations

import (
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
)

// Connect to the database

// Check if "ourtable" exists
// If "ourtable" exists, read migrations out by name
// If "ourtable" doesn't exist, create "ourtable"

// Find migrations in list
// Find migrations in "ourtable"
// For each migration in list, check if it exists in "ourtable"
// If it exists, validate that it hasn't changed
// If it doesn't exist, run it -- UP

// MigrationsTable is the name of the table that tracks applied migrations.
const MigrationsTableName = "schema_migrations"

const migrationsTable = `
CREATE TABLE IF NOT EXISTS %s.%s (
	name varchar PRIMARY KEY,
	checksum varchar,
	succeeded boolean,
	execution_completed timestamp
)
`

type migrationFile struct {
	name     string
	hash     string
	contents []byte
}

func RunMigrations(ctx context.Context, keyspace string, session *gocql.Session, migrationsDir fs.FS) error {
	migrationsTableQuery := fmt.Sprintf(migrationsTable, keyspace, MigrationsTableName)

	if err := session.Query(migrationsTableQuery).ExecContext(ctx); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	var migrationFiles []migrationFile

	entries, err := fs.ReadDir(migrationsDir, ".")
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		migrationBytes, err := fs.ReadFile(migrationsDir, entry.Name())
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", entry.Name(), err)
		}

		migrationHash := hashMigration(migrationBytes)
		migrationFiles = append(migrationFiles, migrationFile{
			name:     entry.Name(),
			hash:     migrationHash,
			contents: migrationBytes,
		})
	}

	slices.SortFunc(migrationFiles, func(a, b migrationFile) int {
		return strings.Compare(a.name, b.name)
	})

	for _, migration := range migrationFiles {
		var (
			existingChecksum string
			succeeded        bool
		)

		err := session.Query(
			fmt.Sprintf("SELECT checksum, succeeded FROM %s.%s WHERE name = ?", keyspace, MigrationsTableName),
			migration.name,
		).ScanContext(ctx, &existingChecksum, &succeeded)
		if err != nil {
			if !errors.Is(err, gocql.ErrNotFound) {
				return fmt.Errorf("failed to query for existing migration %s: %w", migration.name, err)
			}
		} else {
			if existingChecksum != migration.hash {
				return fmt.Errorf("migration %s has been modified since it was applied", migration.name)
			}
			if !succeeded {
				return fmt.Errorf("previous attempt to apply migration %s failed", migration.name)
			}
		}

		stmts := make([][]byte, 0)
		for i := 0; i < len(migration.contents); i++ {
			if len(stmts) == 0 {
				stmts = append(stmts, []byte{})
			}

			if migration.contents[i] == ';' {
				stmts = append(stmts, []byte{})
				continue
			}

			stmts[len(stmts)-1] = append(stmts[len(stmts)-1], migration.contents[i])
		}

		for i := 0; i < len(stmts); i++ {
			if len(stmts[i]) == 0 {
				continue
			}

			if migrateErr := session.Query(string(stmts[i])).SetKeyspace(keyspace).Consistency(gocql.Quorum).ExecContext(ctx); migrateErr != nil {
				if execErr := session.Query(
					fmt.Sprintf("INSERT INTO %s.%s (name, checksum, succeeded, execution_completed) VALUES (?, ?, ?, toTimestamp(now()))", keyspace, MigrationsTableName),
					migration.name, migration.hash, false,
				).ExecContext(ctx); execErr != nil {
					return fmt.Errorf("failed to record failed migration %s: %w (original error: %v)", migration.name, execErr, migrateErr)
				}
				return fmt.Errorf("failed to apply migration %s: %w", migration.name, migrateErr)
			}
		}

		if err := session.Query(
			fmt.Sprintf("INSERT INTO %s.%s (name, checksum, succeeded, execution_completed) VALUES (?, ?, ?, toTimestamp(now()))", keyspace, MigrationsTableName),
			migration.name, migration.hash, true,
		).ExecContext(ctx); err != nil {
			return fmt.Errorf("failed to record successful migration %s: %w", migration.name, err)
		}
	}

	return nil
}

func hashMigration(migrationBytes []byte) string {
	s := sha1.Sum(migrationBytes)
	return fmt.Sprintf("%x", s)
}
