package qb

type QueryType string

const (
	Insert QueryType = "INSERT"
	Update QueryType = "UPDATE"
	Select QueryType = "SELECT"
	Delete QueryType = "DELETE"
)

type QueryBuilder interface {
	Build() (string, error)
	QueryValues() []any
}
