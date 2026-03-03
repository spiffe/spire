package qb

import "strings"

type InsertBuilder interface {
	QueryBuilder

	Into(table string) InsertBuilder
	Columns(columns ...string) InsertBuilder
	Values(values ...any) InsertBuilder
	IfNotExists() InsertBuilder
	Build() (string, error)
}

type insertBuilder struct {
	table       string
	columns     []string
	values      []any
	ifNotExists bool
}

func NewInsert() InsertBuilder {
	return &insertBuilder{}
}

func (b *insertBuilder) Into(table string) InsertBuilder {
	b.table = table
	return b
}

func (b *insertBuilder) Columns(columns ...string) InsertBuilder {
	b.columns = append(b.columns, columns...)
	return b
}

func (b *insertBuilder) Values(values ...any) InsertBuilder {
	b.values = append(b.values, values...)
	return b
}

func (b *insertBuilder) IfNotExists() InsertBuilder {
	b.ifNotExists = true
	return b
}

func (b *insertBuilder) Build() (string, error) {
	return buildInsertFrom(b)
}

func (b *insertBuilder) QueryValues() []any {
	vals := make([]any, 0, len(b.values))
	for _, v := range b.values {
		if _, ok := v.(literal); !ok {
			vals = append(vals, v)
		}
	}
	return vals
}

func buildInsertFrom(b *insertBuilder) (string, error) {
	sb := strings.Builder{}
	sb.WriteString("INSERT INTO ")
	sb.WriteString(b.table)
	sb.WriteString(" (")

	for i, col := range b.columns {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(col)
	}

	sb.WriteString(") VALUES (")

	for i := range b.values {
		if i > 0 {
			sb.WriteString(", ")
		}

		if literal, ok := b.values[i].(literal); ok {
			if literal.singleQuote {
				sb.WriteString("'")
			}
			sb.WriteString(literal.value)
			if literal.singleQuote {
				sb.WriteString("'")
			}
		} else {
			sb.WriteString("?")
		}
	}

	sb.WriteString(")")

	if b.ifNotExists {
		sb.WriteString(" IF NOT EXISTS")
	}

	return sb.String(), nil
}
