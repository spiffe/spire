package log

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalTimeHook(t *testing.T) {
	baseTime := time.Date(2021, 1, 1, 12, 0, 0, 0, time.UTC)

	localTimeSamples := map[string]string{
		"UTC":               "2021-01-01 12:00:00 +0000 UTC",
		"America/Sao_Paulo": "2021-01-01 09:00:00 -0300 -03",
		"America/New_York":  "2021-01-01 07:00:00 -0500 EST",
		"Africa/Cairo":      "2021-01-01 14:00:00 +0200 EET",
		"Asia/Tokyo":        "2021-01-01 21:00:00 +0900 JST",
		"Europe/London":     "2021-01-01 12:00:00 +0000 GMT",
		"Australia/Sydney":  "2021-01-01 23:00:00 +1100 AEDT",
	}

	testHook := test.Hook{}
	logger, err := NewLogger(
		func(logger *Logger) error {
			logger.AddHook(&testHook)
			return nil
		})
	require.NoError(t, err)

	for tz, expected := range localTimeSamples {
		t.Run(tz, func(t *testing.T) {
			time.Local, err = time.LoadLocation(tz)
			require.NoError(t, err)

			logger.
				WithField("time", baseTime).
				WithField("timePointer", &baseTime).
				WithField("unixTime", baseTime.Unix()).
				Info("Info log with time and string fields")

			assert.Equalf(t,
				expected,
				testHook.LastEntry().Data["time"].(time.Time).String(),
				"Timezone should be in %s format", tz,
			)
			assert.Equalf(t,
				expected,
				testHook.LastEntry().Data["timePointer"].(*time.Time).String(),
				"Timezone should be in %s format", tz,
			)
			assert.Equalf(t,
				int64(1609502400),
				testHook.LastEntry().Data["unixTime"].(int64),
				"other field types should be unchanged")
		})
	}
}

// Basic smoketest: set up a logger, make sure options work
func TestLogger(t *testing.T) {
	testHook := test.Hook{}

	// Set up a logger with a test hook
	logger, err := NewLogger(WithLevel("warning"),
		func(logger *Logger) error {
			logger.AddHook(&testHook)
			return nil
		})
	require.NoError(t, err)

	logger.Info("Info should be discarded, as it's below warn")

	require.Empty(t, testHook.Entries)

	msg := "Expected warning"
	logger.Warning(msg)

	require.Equal(t, msg, testHook.LastEntry().Message)
}

// Make sure writing to an output file works with various formats
func TestOutputFile(t *testing.T) {
	msg := "This should get written"

	for _, format := range []string{DefaultFormat, TextFormat, JSONFormat} {
		f, err := os.CreateTemp("", "testoutputfile")
		require.NoError(t, err)
		tmpfile := f.Name()
		defer os.Remove(tmpfile)

		logger, err := NewLogger(WithOutputFile(tmpfile), WithFormat(format))
		require.NoError(t, err)

		logger.Warning(msg)

		require.NoError(t, logger.Close())

		log, err := io.ReadAll(f)
		require.NoError(t, err)

		if format == JSONFormat {
			var data map[string]string
			require.NoError(t, json.Unmarshal(log, &data))
			assert.Equal(t, data["level"], "warning")
			assert.Equal(t, data["msg"], msg)
			assert.Contains(t, data, "time")
			assert.EqualValues(t, len(data), 3, "%q", data)
		} else {
			expected := fmt.Sprintf("level=warning msg=\"%s\"", msg)
			require.Contains(t, string(log), expected)
		}
	}
}

// Make sure writing to reopenable logfile behaves identically to static file.
func TestReopenableOutputFile(t *testing.T) {
	msg := "This should get written"

	for _, format := range []string{DefaultFormat, TextFormat, JSONFormat} {
		f, err := os.CreateTemp("", "testoutputfile")
		require.NoError(t, err)
		tmpfile := f.Name()
		defer os.Remove(tmpfile)

		reopenableFile, err := NewReopenableFile(f.Name())
		require.NoError(t, err)

		logger, err := NewLogger(WithReopenableOutputFile(reopenableFile), WithFormat(format))
		require.NoError(t, err)

		logger.Warning(msg)

		require.NoError(t, logger.Close())

		log, err := io.ReadAll(f)
		require.NoError(t, err)

		if format == JSONFormat {
			var data map[string]string
			require.NoError(t, json.Unmarshal(log, &data))
			assert.Equal(t, data["level"], "warning")
			assert.Equal(t, data["msg"], msg)
			assert.Contains(t, data, "time")
			assert.EqualValues(t, len(data), 3, "%q", data)
		} else {
			expected := fmt.Sprintf("level=warning msg=\"%s\"", msg)
			require.Contains(t, string(log), expected)
		}
	}
}
