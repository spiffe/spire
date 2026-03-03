package qb

import (
	"errors"
	"strconv"
	"strings"
)

type selectBuilder struct {
	cols            []string
	retrieveColumns map[string]struct{}
	verb            QueryType
	table           string
	filterTerms     []*filterTerm
	limit           uint
	values          []any
	queryValues     []any
	allowFiltering  bool
	isDistinct      bool
}

func (b *selectBuilder) Column(name string) SelectBuilder {
	if b.retrieveColumns == nil {
		b.retrieveColumns = make(map[string]struct{})
	}

	if _, exists := b.retrieveColumns[name]; exists {
		return b
	}

	b.retrieveColumns[name] = struct{}{}
	b.cols = append(b.cols, name)

	return b
}

func (b *selectBuilder) Columns(names []string) SelectBuilder {
	if b.retrieveColumns == nil {
		b.retrieveColumns = make(map[string]struct{})
	}

	for _, name := range names {
		b.Column(name)
	}

	return b
}

func (b *selectBuilder) From(table string) SelectBuilder {
	b.table = table

	return b
}

func (b *selectBuilder) Where(column string, ft filterTerm) SelectBuilder {
	ft.column = column

	b.filterTerms = append(b.filterTerms, &ft)

	return b
}

func (b *selectBuilder) Limit(num uint) SelectBuilder {
	b.limit = num

	return b
}

func (b *selectBuilder) Build() (string, error) {
	switch b.verb {
	case Select:
		return buildSelectFrom(b)
	}

	return "", errors.New("Not implemented")
}

func buildSelectFrom(b *selectBuilder) (string, error) {
	q := strings.Builder{}
	q.WriteString("SELECT ")
	if b.isDistinct {
		q.WriteString("DISTINCT ")
	}

	for i, col := range b.cols { // ordinal is important for scanning
		if i > 0 {
			q.WriteString(", ")
		}
		q.WriteString(col)
	}
	if len(b.cols) == 0 {
		q.WriteString("*")
	}

	q.WriteString(" FROM ")
	q.WriteString(b.table)

	for i := range b.filterTerms {
		if i == 0 {
			q.WriteString(" WHERE ")
		} else {
			q.WriteString(" AND ")
		}

		q.WriteString(b.filterTerms[i].column)
		q.WriteString(" ")
		q.WriteString(string(b.filterTerms[i].operator))
		q.WriteString(" ")

		switch {
		case b.filterTerms[i].value != nil:
			q.WriteString("?")
			b.queryValues = append(b.queryValues, b.filterTerms[i].value)
		case b.filterTerms[i].values != nil:
			q.WriteString("(")

			for j := range b.filterTerms[i].values {
				if j > 0 {
					q.WriteString(", ")
				}
				q.WriteString("?")
				b.queryValues = append(b.queryValues, b.filterTerms[i].values[j])
			}
			q.WriteString(")")
		case b.filterTerms[i].deepValues != nil:
			q.WriteString("(")
			for j := range b.filterTerms[i].deepValues {
				if j > 0 {
					q.WriteString(", ")
				}
				q.WriteString("?")
				b.queryValues = append(b.queryValues, b.filterTerms[i].deepValues[j])
			}
			q.WriteString(")")
		}
	}

	if b.limit > 0 {
		q.WriteString(" LIMIT ")
		q.WriteString(strconv.Itoa(int(b.limit)))
	}

	if b.allowFiltering {
		q.WriteString(" ALLOW FILTERING")
	}

	// TODO(tjons): grab these builders from a mempool
	// also, validate
	return q.String(), nil
}

func (b *selectBuilder) AllowFiltering() SelectBuilder {
	b.allowFiltering = true
	return b
}

func (b *selectBuilder) Distinct() SelectBuilder {
	b.isDistinct = true
	return b
}

func (b *selectBuilder) QueryValues() []any {
	return b.queryValues
}

type SelectBuilder interface {
	QueryBuilder

	Distinct() SelectBuilder
	Column(string) SelectBuilder
	Columns([]string) SelectBuilder
	From(string) SelectBuilder
	Where(string, filterTerm) SelectBuilder
	Limit(uint) SelectBuilder
	AllowFiltering() SelectBuilder
}

func NewSelect() SelectBuilder {
	return &selectBuilder{verb: Select}
}
