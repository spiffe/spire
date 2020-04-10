package mysqlkv

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"sync"

	_ "github.com/go-sql-driver/mysql"
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
}

func Open(source string) (_ *KV, err error) {
	db, err := sql.Open("mysql", source)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	defer func() {
		if err != nil {
			_ = db.Close()
		}
	}()

	// TODO: migration

	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS kv(k VARBINARY(4096) NOT NULL, v BLOB);"); err != nil {
		return nil, errs.Wrap(err)
	}

	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS kv_k_idx ON kv(k ASC) USING BTREE;"); err != nil {
		return nil, errs.Wrap(err)
	}

	get, err := db.Prepare("SELECT v FROM kv WHERE k = ?")
	if err != nil {
		return nil, errs.Wrap(err)
	}
	defer func() {
		if err != nil {
			_ = get.Close()
		}
	}()

	put, err := db.Prepare("REPLACE INTO kv(k,v) VALUES(?, ?)")
	if err != nil {
		return nil, errs.Wrap(err)
	}
	defer func() {
		if err != nil {
			_ = put.Close()
		}
	}()

	delete, err := db.Prepare("DELETE FROM kv WHERE k=?")
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
	return put(ctx, kv.put, key, value)
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
	kv *KV
	tx *sql.Tx
}

func (tx *Tx) Get(ctx context.Context, key []byte) ([]byte, error) {
	return get(ctx, tx.tx.Stmt(tx.kv.get), key)
}

func (tx *Tx) Put(ctx context.Context, key, value []byte) error {
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
	return errs.Wrap(tx.tx.Commit())
}

func (tx *Tx) Rollback() error {
	return errs.Wrap(tx.tx.Commit())
}

func (tx *Tx) prepare(s string) (*sql.Stmt, error) {
	stmt, err := tx.kv.prepare(s)
	if err != nil {
		return nil, err
	}
	return tx.tx.Stmt(stmt), nil
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
	buf.WriteString("SELECT kv.k, kv.v FROM kv WHERE kv.k > ? AND kv.k <= concat(?, '\xff') ORDER BY kv.k ASC")
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
	buf := new(strings.Builder)
	buf.WriteString("SELECT k, v FROM kv WHERE k IN (\n")
	buf.WriteString("\tSELECT DISTINCT ind FROM\n")
	for i, index := range indices {
		if i > 0 {
			buf.WriteString("\t\tINNER JOIN\n")
		}

		buf.WriteString("\t\t(")
		if len(index.Prefixes) == 1 {
			buf.WriteString("SELECT substr(k,length(?)+1) AS ind FROM kv WHERE k > ? AND k <= concat(?, '\xff')")
			buf.WriteString(") q_")
		} else {
			buf.WriteString("\n")
			switch index.SetOp {
			case protokv.SetUnion:
				for j := range index.Prefixes {
					if j > 0 {
						buf.WriteString("\t\tUNION\n")
					}
					buf.WriteString("\t\tSELECT substr(k,length(?)+1) AS ind FROM kv WHERE k > ? AND k <= concat(?, '\xff')\n")
				}
			case protokv.SetIntersect:
				buf.WriteString("\t\t\tSELECT DISTINCT ind FROM \n")
				for j := range index.Prefixes {
					if j > 0 {
						buf.WriteString("\t\t\tINNER JOIN\n")
					}
					buf.WriteString("\t\t\t(SELECT substr(k,length(?)+1) AS ind FROM kv WHERE k > ? AND k <= concat(?, '\xff')) q_")
					buf.WriteString(strconv.Itoa(i))
					buf.WriteString("_")
					buf.WriteString(strconv.Itoa(j))
					buf.WriteString("\n")
					if j > 0 {
						buf.WriteString("\t\t\tUSING(ind)\n")
					}
				}
			default:
				return nil, nil, errs.New("unsupported set op: %q", index.SetOp)
			}
			buf.WriteString("\t\t) q_")
		}
		buf.WriteString(strconv.Itoa(i))
		buf.WriteString("\n")
		if i > 0 {
			buf.WriteString("\t\tUSING(ind)\n")
		}
	}
	buf.WriteString(")")

	var args []interface{}
	for _, index := range indices {
		for _, prefix := range index.Prefixes {
			args = append(args, prefix, prefix, prefix)
		}
	}

	if len(token) > 0 {
		buf.WriteString(" WHERE kv.k > ?\n")
		args = append(args, token)
	}
	buf.WriteString(" ORDER BY kv.k\n")
	if limit > 0 {
		buf.WriteString(" LIMIT ")
		buf.WriteString(strconv.Itoa(limit))
		buf.WriteString("\n")
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
