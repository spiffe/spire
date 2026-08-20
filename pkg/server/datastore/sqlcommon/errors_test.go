package sqlcommon

import (
	"errors"
	"testing"
)

func TestSQLErrorPrefixesAndUnwrap(t *testing.T) {
	base := errors.New("boom")
	if got := NewWrappedSQLError(base).Error(); got != "datastore-sql: boom" {
		t.Fatalf("got %q", got)
	}
	if !errors.Is(NewWrappedSQLError(base), base) {
		t.Fatal("wrapped SQL error should unwrap to base")
	}
	if got := NewValidationError("bad %d", 7).Error(); got != "datastore-validation: bad 7" {
		t.Fatalf("got %q", got)
	}
	if NewWrappedSQLError(nil) != nil {
		t.Fatal("nil in => nil out")
	}
	if got := NewSQLError("bad %d", 3).Error(); got != "datastore-sql: bad 3" {
		t.Fatalf("got %q", got)
	}
	if got := NewWrappedValidationError(base).Error(); got != "datastore-validation: boom" {
		t.Fatalf("got %q", got)
	}
	if !errors.Is(NewWrappedValidationError(base), base) {
		t.Fatal("wrapped validation error should unwrap to base")
	}
	if NewWrappedValidationError(nil) != nil {
		t.Fatal("nil in => nil out")
	}
}
