package qb

import "strings"

type UpdateBuilder interface {
	QueryBuilder

	Table(name string) UpdateBuilder
	Set(column string, value any) UpdateBuilder
	Where(condition string, value filterTerm) UpdateBuilder
	IfExists() UpdateBuilder
	Build() (string, error)
}

type updateBuilder struct {
	table        string
	columns      []string
	columnValues []any
	conditions   []filterTerm
	ifExists     bool
	queryValues  []any
}

func NewUpdate() UpdateBuilder {
	return &updateBuilder{}
}

func (b *updateBuilder) Table(name string) UpdateBuilder {
	b.table = name
	return b
}

func (b *updateBuilder) Set(column string, value any) UpdateBuilder { // TODO(tjons): this needs to be able to accept more than just a single value, like setting a collection type...
	b.columns = append(b.columns, column)
	b.columnValues = append(b.columnValues, value)
	return b
}

func (b *updateBuilder) Where(column string, ft filterTerm) UpdateBuilder {
	ft.column = column
	b.conditions = append(b.conditions, ft)

	return b
}

func (b *updateBuilder) IfExists() UpdateBuilder {
	b.ifExists = true
	return b
}

func (b *updateBuilder) Build() (string, error) {
	return buildUpdateFrom(b)
}

// TODO(tjons): clean this up, I don't think skippedLiteral* is as relevant for the UPDATE clause
func (b *updateBuilder) QueryValues() []any {
	// preallocate slice with the most elements we might need
	vals := make([]any, len(b.columnValues)+len(b.conditions))
	if len(vals) == 0 {
		return nil
	}

	var skippedLiteralColumns, skippedLiteralConditions int
	for i := range b.columnValues {
		if _, ok := b.columnValues[i].(literal); ok {
			skippedLiteralColumns++
		} else {
			vals[i-skippedLiteralColumns] = b.columnValues[i]
		}
	}

	offset := len(b.columnValues) - skippedLiteralColumns
	for i := range b.conditions {
		vals[offset+i-skippedLiteralConditions] = b.conditions[i].value
	}

	// chop off unused elements
	return vals[:len(vals)-skippedLiteralColumns-skippedLiteralConditions]
}

func buildUpdateFrom(b *updateBuilder) (string, error) {
	sb := strings.Builder{}
	sb.WriteString("UPDATE ")
	sb.WriteString(b.table)
	sb.WriteString(" SET ")
	for i := range b.columns {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(b.columns[i])
		sb.WriteString(" = ")
		if literal, ok := b.columnValues[i].(literal); ok {
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

	sb.WriteString(" WHERE ")

	for i := range b.conditions {
		if i > 0 {
			sb.WriteString(" AND ")
		}

		sb.WriteString(b.conditions[i].column)
		sb.WriteString(" = ")

		if len(b.conditions[i].values) > 0 {
			sb.WriteString("(")
			for j := range b.conditions[i].values {
				if j > 0 {
					sb.WriteString(", ")
				}
				sb.WriteString("?")
			}
			sb.WriteString(")")
		} else {
			sb.WriteString("?")
		}
	}

	if b.ifExists {
		sb.WriteString(" IF EXISTS")
	}

	return sb.String(), nil
}
