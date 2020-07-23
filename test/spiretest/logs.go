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
	for _, entry := range entries {
		for key, field := range entry.Data {
			entry.Data[key] = fmt.Sprint(field)
		}
	}

	assert.Equal(t, expected, convertLogEntries(entries), "unexpected logs")
}

func AssertLogsAnyOrder(t *testing.T, entries []*logrus.Entry, expected []LogEntry) {
	for _, entry := range entries {
		for key, field := range entry.Data {
			entry.Data[key] = fmt.Sprint(field)
		}
	}

	assert.ElementsMatch(t, expected, convertLogEntries(entries), "unexpected logs")
}

func convertLogEntries(entries []*logrus.Entry) (out []LogEntry) {
	for _, entry := range entries {
		out = append(out, LogEntry{
			Level:   entry.Level,
			Message: entry.Message,
			Data:    fieldsOrNil(entry.Data),
		})
	}
	return out
}

func fieldsOrNil(data logrus.Fields) logrus.Fields {
	if len(data) > 0 {
		return data
	}
	return nil
}
