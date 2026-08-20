package spiretest

import (
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type LogEntry struct {
	Level   logrus.Level
	Message string
	Data    logrus.Fields
}

func AssertLogs(t *testing.T, entries []*logrus.Entry, expected []LogEntry) {
	t.Helper()
	assert.Equal(t, expected, convertLogEntries(entries), "unexpected logs")
}

func AssertLogsAnyOrder(t *testing.T, entries []*logrus.Entry, expected []LogEntry) {
	t.Helper()
	assert.ElementsMatch(t, expected, convertLogEntries(entries), "unexpected logs")
}

func AssertLastLogs(t *testing.T, entries []*logrus.Entry, expected []LogEntry) {
	t.Helper()
	removeLen := len(entries) - len(expected)
	if removeLen > 0 {
		assert.Equal(t, expected, convertLogEntries(entries[removeLen:]), "unexpected logs")
		return
	}
	assert.Equal(t, expected, convertLogEntries(entries), "unexpected logs")
}

func AssertLogsContainEntries(t *testing.T, entries []*logrus.Entry, expectedEntries []LogEntry) {
	t.Helper()
	if len(expectedEntries) == 0 {
		return
	}

	logEntries := convertLogEntries(entries)
	for _, entry := range expectedEntries {
		assert.Contains(t, logEntries, entry)
	}
}

func convertLogEntries(entries []*logrus.Entry) (out []LogEntry) {
	for _, entry := range entries {
		out = append(out, LogEntry{
			Level:   entry.Level,
			Message: entry.Message,
			Data:    normalizeData(entry.Data),
		})
	}
	return out
}

func normalizeData(data logrus.Fields) logrus.Fields {
	if len(data) == 0 {
		return nil
	}
	// Build a new map rather than mutating the caller's. The entries come
	// from a logrus hook that shares each entry's Data map with logrus
	// itself, so a background goroutine may still be formatting (reading)
	// the same map while we normalize it. Mutating in place would race.
	out := make(logrus.Fields, len(data))
	for key, field := range data {
		out[key] = fmt.Sprint(field)
	}
	return out
}
