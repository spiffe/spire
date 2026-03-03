package qb

import "strings"

type DeleteBuilder interface {
	QueryBuilder

	Column(column string) DeleteBuilder
	From(table string) DeleteBuilder
	Where(column string, ft filterTerm) DeleteBuilder
	IfExists() DeleteBuilder
	Build() (string, error)
}

type deleteBuilder struct {
	columns     []string
	table       string
	filterTerms []*filterTerm
	ifExists    bool
	queryValues []any
}

func NewDelete() DeleteBuilder {
	return &deleteBuilder{}
}

func (b *deleteBuilder) Column(column string) DeleteBuilder {
	b.columns = append(b.columns, column)

	return b
}

func (b *deleteBuilder) IfExists() DeleteBuilder {
	b.ifExists = true

	return b
}

func (b *deleteBuilder) From(table string) DeleteBuilder {
	b.table = table

	return b
}

func (b *deleteBuilder) Where(column string, ft filterTerm) DeleteBuilder {
	ft.column = column
	b.filterTerms = append(b.filterTerms, &ft)

	return b
}

func (b *deleteBuilder) Build() (string, error) {
	return buildDeleteFrom(b)
}

func buildDeleteFrom(b *deleteBuilder) (string, error) {
	var sb strings.Builder

	sb.WriteString("DELETE ")
	for i := range b.columns {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(b.columns[i])
	}
	sb.WriteString(" FROM ")
	sb.WriteString(b.table)

	for i := range b.filterTerms {
		if i == 0 {
			sb.WriteString(" WHERE ")
		} else {
			sb.WriteString(" AND ")
		}

		sb.WriteString(b.filterTerms[i].column)
		sb.WriteString(" ")
		sb.WriteString(string(b.filterTerms[i].operator))
		sb.WriteString(" ")

		switch {
		case b.filterTerms[i].value != nil:
			sb.WriteString("?")
			b.queryValues = append(b.queryValues, b.filterTerms[i].value)
		case b.filterTerms[i].values != nil:
			sb.WriteString("(")
			for j := range b.filterTerms[i].values {
				if j > 0 {
					sb.WriteString(", ")
				}
				sb.WriteString("?")
				b.queryValues = append(b.queryValues, b.filterTerms[i].values[j])
			}
			sb.WriteString(")")
		case b.filterTerms[i].deepValues != nil:
			sb.WriteString("(")
			for j := range b.filterTerms[i].deepValues {
				if j > 0 {
					sb.WriteString(", ")
				}
				sb.WriteString("?")
				b.queryValues = append(b.queryValues, b.filterTerms[i].deepValues[j])
			}
			sb.WriteString(")")
		}
	}

	if b.ifExists {
		sb.WriteString(" IF EXISTS")
	}

	return sb.String(), nil
}

func (b *deleteBuilder) QueryValues() []any {
	return b.queryValues
}
