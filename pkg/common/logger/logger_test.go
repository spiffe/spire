package logger

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Desired order
// "" always first
// a.b before a.b.c
// a.b before a.c
// a.b before b.b
func TestSortByName(t *testing.T) {
	var tests = []struct {
		First  string
		Second string
	}{
		{ "", "a"},
		{"0", "1"},
		{"02", "1"},
		{"1", "a"},
		{"a", "aa"},
		{"a", "ab"},
		{"aa", "ab"},
		{"aa", "abc"},
		{"ab", "abc"},
		{"a.b", "aa.c"},
		{"a.b.c", "aa.a"},
		{"a.b", "a.c"},
	}
	for _, testCase := range tests {
		first := loggerRecord{
			name: testCase.First,
		}
		second := loggerRecord{
			name: testCase.Second,
		}
		require.True(t, sortByName(first, second), "Name %s sould come before %s", first.name, second.name)
		require.False(t, sortByName(second, first), "Name %s sould come after %s", second.name, first.name)
	}
}
