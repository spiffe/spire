package sqltest

// RawQuerier is the escape hatch for tests needing raw SQL access without
// going through ORM models. Implementations back it with their own DB handle.
type RawQuerier interface {
	RawScan(dest any, query string) error
	RawExec(query string, args ...any) error
	DatabaseType() string
}
