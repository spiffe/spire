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
	assert.Equal(t, expected, convertLogEntries(entries), "unexpected logs")
}

func AssertLogsAnyOrder(t *testing.T, entries []*logrus.Entry, expected []LogEntry) {
	assert.ElementsMatch(t, expected, convertLogEntries(entries), "unexpected logs")
}

func AssertLastLogs(t *testing.T, entries []*logrus.Entry, expected []LogEntry) {
	removeLen := len(entries) - len(expected)
	if removeLen > 0 {
		assert.Equal(t, expected, convertLogEntries(entries[removeLen:]), "unexpected logs")
		return
	}
	assert.Equal(t, expected, convertLogEntries(entries), "unexpected logs")
}

func AssertLogsContainEntries(t *testing.T, entries []*logrus.Entry, expectedEntries []LogEntry) {
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
	for key, field := range data {
		data[key] = fmt.Sprint(field)
	}
	return data
}
