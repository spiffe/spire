package spiretest

import (
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// NonZeroTTL acts as a semaphore for matching non-zero "ttl" log fields.
const NonZeroTTL = "nonzero"

type LogEntry struct {
	Level   logrus.Level
	Message string
	Data    logrus.Fields
}

func AssertLogs(t *testing.T, entries []*logrus.Entry, expected []LogEntry) {
	t.Helper()
	assert.Equal(t, expected, convertLogEntries(entries, false), "unexpected logs")
}

func AssertLogsWithNonZeroTTL(t *testing.T, entries []*logrus.Entry, expected []LogEntry, nonZeroTTL bool) {
	t.Helper()
	assert.Equal(t, expected, convertLogEntries(entries, nonZeroTTL), "unexpected logs")
}

func AssertLogsAnyOrder(t *testing.T, entries []*logrus.Entry, expected []LogEntry) {
	t.Helper()
	assert.ElementsMatch(t, expected, convertLogEntries(entries, false), "unexpected logs")
}

func AssertLastLogs(t *testing.T, entries []*logrus.Entry, expected []LogEntry) {
	t.Helper()
	removeLen := len(entries) - len(expected)
	if removeLen > 0 {
		assert.Equal(t, expected, convertLogEntries(entries[removeLen:], false), "unexpected logs")
		return
	}
	assert.Equal(t, expected, convertLogEntries(entries, false), "unexpected logs")
}

func AssertLogsContainEntries(t *testing.T, entries []*logrus.Entry, expectedEntries []LogEntry) {
	t.Helper()
	if len(expectedEntries) == 0 {
		return
	}

	logEntries := convertLogEntries(entries, false)
	for _, entry := range expectedEntries {
		assert.Contains(t, logEntries, entry)
	}
}

func convertLogEntries(entries []*logrus.Entry, nonZeroTTL bool) (out []LogEntry) {
	for _, entry := range entries {
		out = append(out, LogEntry{
			Level:   entry.Level,
			Message: entry.Message,
			Data:    normalizeData(entry.Data, nonZeroTTL),
		})
	}
	return out
}

func normalizeData(data logrus.Fields, nonZeroTTL bool) logrus.Fields {
	if len(data) == 0 {
		return nil
	}
	for key, field := range data {
		if nonZeroTTL && key == "ttl" && data[key] != "0" {
			data[key] = NonZeroTTL
			continue
		}

		data[key] = fmt.Sprint(field)
	}
	return data
}
