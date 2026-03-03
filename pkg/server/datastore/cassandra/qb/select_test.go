package qb_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/spiffe/spire/pkg/server/datastore/cassandra/qb"
)

func TestSelectAll(t *testing.T) {
	expected := `SELECT * FROM test`
	stmt := qb.NewSelect().From("test")

	queryStr, _ := stmt.Build()

	if queryStr != expected {
		t.Error(failureFormatter(expected, queryStr))
	}
}

func TestSelectSingleColumn(t *testing.T) {
	expected := `SELECT entry_id FROM test`
	stmt := qb.NewSelect().From("test").Column("entry_id")

	queryStr, _ := stmt.Build()
	if queryStr != expected {
		t.Error(failureFormatter(expected, queryStr))
	}

	vals := stmt.QueryValues()
	if len(vals) != 0 {
		t.Errorf("expected %d values returned from query, got %d", 0, len(vals))
	}
}

func failureFormatter(expected, actual string) string {
	b := strings.Builder{}
	b.WriteString("\n\nExpected:\n\t")
	b.WriteString(expected)

	b.WriteString("\n\nActual:\n\t")
	b.WriteString(actual)

	return b.String()
}

func TestSelectSingleColumnSingleWhere(t *testing.T) {
	expected := `SELECT entry_id FROM test WHERE entry_id = ?`
	stmt := qb.NewSelect().From("test").Column("entry_id").Where("entry_id", qb.Equals("1"))

	queryStr, _ := stmt.Build()
	if queryStr != expected {
		t.Error(failureFormatter(expected, queryStr))
	}

	checkQueryValues(t, stmt, "1")
}

func TestSelectAllWhereIn(t *testing.T) {
	stmt := qb.NewSelect().From("test").Where("column", qb.In("a", "b", "c"))
	expected := `SELECT * FROM test WHERE column IN (?, ?, ?)`
	expectedVals := []any{"a", "b", "c"}

	queryStr, _ := stmt.Build()
	if expected != queryStr {
		t.Error(failureFormatter(expected, queryStr))
	}

	checkQueryValues(t, stmt, expectedVals...)
}

func TestSelectAllWhereCollectionIn(t *testing.T) {
	stmt := qb.NewSelect().From("test").Where("column", qb.CollectionIn([]any{"a"}, []any{"a", "b"}, []any{"b"}))
	expected := `SELECT * FROM test WHERE column IN (?, ?, ?)`
	expectedVals := []any{[]any{"a"}, []any{"a", "b"}, []any{"b"}}

	queryStr, _ := stmt.Build()
	if expected != queryStr {
		t.Error(failureFormatter(expected, queryStr))
	}

	checkQueryValues(t, stmt, expectedVals...)
}

func checkQueryValues(t *testing.T, stmt qb.QueryBuilder, expectedVals ...any) {
	qvs := stmt.QueryValues()
	if len(qvs) != len(expectedVals) {
		t.Errorf("Expected %+v values in query, got %+v", qvs, expectedVals)
	}

	for i := range qvs {
		if !reflect.DeepEqual(qvs[i], expectedVals[i]) {
			t.Errorf(
				"Expected query elements to be equal, failed at index %d. %+v does not equal %+v",
				i, qvs[i], expectedVals[i])
		}
	}
}
