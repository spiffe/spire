package sql

import (
	"context"
	"database/sql"
	"sync"
)

type stmtCache struct {
	db    *sql.DB
	stmts sync.Map
}

func newStmtCache(db *sql.DB) *stmtCache {
	return &stmtCache{
		db: db,
	}
}

func (cache *stmtCache) get(ctx context.Context, query string) (*sql.Stmt, error) {
	value, loaded := cache.stmts.Load(query)
	if loaded {
		return value.(*sql.Stmt), nil
	}

	stmt, err := cache.db.PrepareContext(ctx, query)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}
	value, loaded = cache.stmts.LoadOrStore(query, stmt)
	if loaded {
		// Somebody beat us to it. Close the statement we prepared.
		stmt.Close()
	}
	return value.(*sql.Stmt), nil
}
