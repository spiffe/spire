package sql

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEmbellishSQLite3ConnString(t *testing.T) {
	testCases := []struct {
		name     string
		in       string
		expected string
	}{
		{
			name:     "non-URI relative path",
			in:       "data.db",
			expected: "file:data.db?_foreign_keys=ON&_journal_mode=WAL",
		},
		{
			name:     "non-URI relative path with directory component",
			in:       "./data.db",
			expected: "file:./data.db?_foreign_keys=ON&_journal_mode=WAL",
		},
		{
			name:     "non-URI absolute path",
			in:       "/home/fred/data.db",
			expected: "file:/home/fred/data.db?_foreign_keys=ON&_journal_mode=WAL",
		},
		{
			name:     "URI with no authority and relative",
			in:       "file:data.db",
			expected: "file:data.db?_foreign_keys=ON&_journal_mode=WAL",
		},
		{
			name:     "URI with no authority and absolute path",
			in:       "file:/home/fred/data.db",
			expected: "file:///home/fred/data.db?_foreign_keys=ON&_journal_mode=WAL",
		},
		{
			name:     "URI with empty authority",
			in:       "file:///home/fred/data.db",
			expected: "file:///home/fred/data.db?_foreign_keys=ON&_journal_mode=WAL",
		},
		{
			name:     "URI with localhost authority",
			in:       "file://localhost/home/fred/data.db",
			expected: "file://localhost/home/fred/data.db?_foreign_keys=ON&_journal_mode=WAL",
		},
		{
			name:     "URI with empty authority and windows file path",
			in:       "file:///C:/Documents%20and%20Settings/fred/Desktop/data.db",
			expected: "file:///C:/Documents%20and%20Settings/fred/Desktop/data.db?_foreign_keys=ON&_journal_mode=WAL",
		},
		{
			name:     "URI with no authority, relative path, and query params",
			in:       "file:data.db?mode=ro",
			expected: "file:data.db?_foreign_keys=ON&_journal_mode=WAL&mode=ro",
		},
		{
			name:     "URI with no authority, absolute path, and query params",
			in:       "file:/home/fred/data.db?vfs=unix-dotfile",
			expected: "file:///home/fred/data.db?_foreign_keys=ON&_journal_mode=WAL&vfs=unix-dotfile",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			actual, err := embellishSQLite3ConnString(testCase.in)
			require.NoError(t, err)
			require.Equal(t, testCase.expected, actual)
		})
	}
}
