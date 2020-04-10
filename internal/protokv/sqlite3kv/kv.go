package sqlite3kv

import (
	"context"
	"database/sql"
	"net/url"
	"strconv"
	"strings"
	"sync"

	_ "github.com/mattn/go-sqlite3"
	"github.com/spiffe/spire/internal/protokv"
	"github.com/zeebo/errs"
)

type KV struct {
	db     *sql.DB
	get    *sql.Stmt
	put    *sql.Stmt
	delete *sql.Stmt

	stmts sync.Map

	closeOnce sync.Once
	writeMu   sync.Mutex
}

var _ protokv.KV = (*KV)(nil)

func Open(source string) (_ *KV, err error) {
	db, err := open(source)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	defer func() {
		if err != nil {
			_ = db.Close()
		}
	}()

	// TODO: migration

	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS kv(key TEXT UNIQUE COLLATE BINARY NOT NULL, value BLOB);"); err != nil {
		return nil, errs.Wrap(err)
	}

	if _, err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS kv_key ON kv(key);"); err != nil {
		return nil, errs.Wrap(err)
	}

	get, err := db.Prepare("SELECT value FROM kv WHERE key = ?")
	if err != nil {
		return nil, errs.Wrap(err)
	}
	defer func() {
		if err != nil {
			_ = get.Close()
		}
	}()

	put, err := db.Prepare("INSERT INTO kv(key,value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
	if err != nil {
		return nil, errs.Wrap(err)
	}
	defer func() {
		if err != nil {
			_ = put.Close()
		}
	}()

	delete, err := db.Prepare("DELETE FROM kv WHERE key=?")
	if err != nil {
		return nil, errs.Wrap(err)
	}
	defer func() {
		if err != nil {
			_ = delete.Close()
		}
	}()

	return &KV{
		db:     db,
		get:    get,
		put:    put,
		delete: delete,
	}, nil
}

func (kv *KV) Close() error {
	var errGroup errs.Group
	kv.closeOnce.Do(func() {
		kv.stmts.Range(func(key, value interface{}) bool {
			errGroup.Add(value.(*sql.Stmt).Close())
			return true
		})
		errGroup.Add(kv.delete.Close())
		errGroup.Add(kv.put.Close())
		errGroup.Add(kv.get.Close())
		errGroup.Add(kv.db.Close())
	})
	return errGroup.Err()
}

func (kv *KV) Get(ctx context.Context, key []byte) ([]byte, error) {
	return get(ctx, kv.get, key)
}

func (kv *KV) Put(ctx context.Context, key, value []byte) error {
	kv.writeMu.Lock()
	err := put(ctx, kv.put, key, value)
	kv.writeMu.Unlock()
	return err
}

func (kv *KV) Page(ctx context.Context, prefix, token []byte, limit int) ([][]byte, []byte, error) {
	return page(ctx, kv.prepare, prefix, token, limit)
}

func (kv *KV) PageIndex(ctx context.Context, indices []protokv.Index, token []byte, limit int) ([][]byte, []byte, error) {
	return pageIndex(ctx, kv.prepare, indices, token, limit)
}

func (kv *KV) Delete(ctx context.Context, key []byte) (bool, error) {
	return delete(ctx, kv.delete, key)
}

func (kv *KV) Begin(ctx context.Context) (protokv.Tx, error) {
	tx, err := kv.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return &Tx{
		kv: kv,
		tx: tx,
	}, nil
}

func (kv *KV) prepare(s string) (*sql.Stmt, error) {
	stmtValue, ok := kv.stmts.Load(s)
	if ok {
		return stmtValue.(*sql.Stmt), nil
	}
	stmt, err := kv.db.Prepare(s)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	stmtValue, loaded := kv.stmts.LoadOrStore(s, stmt)
	if loaded {
		_ = stmt.Close()
		stmt = stmtValue.(*sql.Stmt)
	}
	return stmt, nil
}

type Tx struct {
	kv          *KV
	tx          *sql.Tx
	writeLocked bool
}

func (tx *Tx) Get(ctx context.Context, key []byte) ([]byte, error) {
	return get(ctx, tx.tx.Stmt(tx.kv.get), key)
}

func (tx *Tx) Put(ctx context.Context, key, value []byte) error {
	if !tx.writeLocked {
		tx.kv.writeMu.Lock()
		tx.writeLocked = true
	}
	return put(ctx, tx.tx.Stmt(tx.kv.put), key, value)
}

func (tx *Tx) Page(ctx context.Context, prefix, token []byte, limit int) ([][]byte, []byte, error) {
	return page(ctx, tx.prepare, prefix, token, limit)
}

func (tx *Tx) PageIndex(ctx context.Context, indices []protokv.Index, token []byte, limit int) ([][]byte, []byte, error) {
	return pageIndex(ctx, tx.prepare, indices, token, limit)
}

func (tx *Tx) Delete(ctx context.Context, key []byte) (bool, error) {
	return delete(ctx, tx.tx.Stmt(tx.kv.delete), key)
}

func (tx *Tx) Commit() error {
	err := errs.Wrap(tx.tx.Commit())
	if tx.writeLocked {
		tx.kv.writeMu.Unlock()
	}
	return err
}

func (tx *Tx) Rollback() error {
	err := errs.Wrap(tx.tx.Rollback())
	if tx.writeLocked {
		tx.kv.writeMu.Unlock()
	}
	return err
}

func (tx *Tx) prepare(s string) (*sql.Stmt, error) {
	stmt, err := tx.kv.prepare(s)
	if err != nil {
		return nil, err
	}
	return tx.tx.Stmt(stmt), nil
}

func open(source string) (*sql.DB, error) {
	u, err := url.Parse(source)
	if err != nil {
		return nil, errs.New("malformed source string: %v", err)
	}

	switch {
	case u.Scheme == "":
		// connection string is a path. move the path section into the
		// opaque section so it renders properly for sqlite3, for example:
		// data.db = file:data.db
		// ./data.db = file:./data.db
		// /data.db = file:/data.db
		u.Scheme = "file"
		u.Opaque, u.Path = u.Path, ""
	case u.Scheme != "file":
		// only no scheme (i.e. file path) or file scheme is supported
		return nil, errs.New("unsupported scheme %q", u.Scheme)
	}

	q := u.Query()
	q.Set("_journal_mode", "WAL")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return db, nil
}

func get(ctx context.Context, stmt *sql.Stmt, key []byte) ([]byte, error) {
	var value []byte
	row := stmt.QueryRowContext(ctx, key)
	if err := row.Scan(&value); err != nil {
		if err == sql.ErrNoRows {
			return nil, protokv.NotFound.New("%q", key)
		}
		return nil, errs.Wrap(err)
	}
	return value, nil
}

func put(ctx context.Context, stmt *sql.Stmt, key, value []byte) error {
	_, err := stmt.ExecContext(ctx, key, value)
	if err != nil {
		return errs.Wrap(err)
	}
	return nil
}

func page(ctx context.Context, prepare func(string) (*sql.Stmt, error), prefix, token []byte, limit int) ([][]byte, []byte, error) {
	args := []interface{}{prefix, prefix}
	if len(token) > 0 {
		args[0] = token
	}

	buf := new(strings.Builder)
	buf.WriteString("SELECT kv.key, kv.value FROM kv WHERE kv.key > ? AND kv.key <= cast(? || '\xff' as BLOB) ORDER BY kv.key asc")
	if limit > 0 {
		buf.WriteString(" LIMIT ")
		buf.WriteString(strconv.Itoa(limit))
	}

	stmt, err := prepare(buf.String())
	if err != nil {
		return nil, nil, errs.Wrap(err)
	}

	rows, err := stmt.QueryContext(ctx, args...)
	if err != nil {
		return nil, nil, errs.Wrap(err)
	}
	defer rows.Close()

	return scanKeyValues(rows, limit)
}

func pageIndex(ctx context.Context, prepare func(string) (*sql.Stmt, error), indices []protokv.Index, token []byte, limit int) ([][]byte, []byte, error) {
	var args []interface{}

	buf := new(strings.Builder)
	buf.WriteString("WITH idx(key) AS (\n")

	for i, index := range indices {
		if i > 0 {
			buf.WriteString("\t\tINTERSECT\n")
		}

		if len(index.Prefixes) == 1 {
			buf.WriteString("\t\tSELECT substr(key,length(?)+1) AS ind FROM kv WHERE key > ? AND key <= cast(? || '\xff' AS BLOB)\n")
		} else {
			if len(indices) > 1 {
				buf.WriteString("\t\tSELECT ind FROM (\n")
			}
			for j := range index.Prefixes {
				if j > 0 {
					if len(indices) > 1 {
						buf.WriteString("\t")
					}
					switch index.SetOp {
					case protokv.SetUnion:
						buf.WriteString("\t\tUNION\n")
					case protokv.SetIntersect:
						buf.WriteString("\t\tINTERSECT\n")
					default:
						return nil, nil, errs.New("unsupported set op: %q", index.SetOp)
					}
				}
				if len(indices) > 1 {
					buf.WriteString("\t")
				}
				buf.WriteString("\t\tSELECT substr(key,length(?)+1) AS ind FROM kv WHERE key > ? AND key <= cast(? || '\xff' AS BLOB)\n")
			}
			if len(indices) > 1 {
				buf.WriteString("\t\t)\n")
			}
		}
		for _, prefix := range index.Prefixes {
			args = append(args, prefix, prefix, prefix)
		}
	}

	buf.WriteString(") SELECT kv.key, kv.value FROM kv INNER JOIN idx ON kv.key=idx.key")
	if len(token) > 0 {
		buf.WriteString(" WHERE kv.key > ?")
		args = append(args, token)
	}
	buf.WriteString(" ORDER BY kv.key")
	if limit > 0 {
		buf.WriteString(" LIMIT ")
		buf.WriteString(strconv.Itoa(limit))
	} else {
		limit = 0
	}

	stmt, err := prepare(buf.String())
	if err != nil {
		return nil, nil, errs.Wrap(err)
	}

	rows, err := stmt.QueryContext(ctx, args...)
	if err != nil {
		return nil, nil, errs.Wrap(err)
	}
	defer rows.Close()

	return scanKeyValues(rows, limit)
}

func delete(ctx context.Context, stmt *sql.Stmt, key []byte) (bool, error) {
	result, err := stmt.ExecContext(ctx, key)
	if err != nil {
		return false, errs.Wrap(err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err)
	}
	return rowsAffected > 0, nil
}

func scanKeyValues(rows *sql.Rows, limit int) ([][]byte, []byte, error) {
	var token []byte
	values := make([][]byte, 0, limit)
	for rows.Next() {
		var value []byte
		if err := rows.Scan(&token, &value); err != nil {
			return nil, nil, errs.Wrap(err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, errs.Wrap(err)
	}
	if len(values) < limit {
		token = nil
	}
	return values, token, nil
}
