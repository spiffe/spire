package log

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

	logger.Info("info should be discarded, as it's below warn")

	require.Empty(t, testHook.Entries)

	msg := "Expected warning"
	logger.Warning(msg)

	require.Equal(t, msg, testHook.LastEntry().Message)
}

// Make sure writing to an output file works with various formats
func TestOutputFile(t *testing.T) {
	msg := "This should get written"

	for _, format := range []string{DefaultFormat, TextFormat, JSONFormat} {
		f, err := ioutil.TempFile("", "testoutputfile")
		require.NoError(t, err)
		tmpfile := f.Name()
		defer os.Remove(tmpfile)

		logger, err := NewLogger(WithOutputFile(tmpfile), WithFormat(format))
		require.NoError(t, err)

		logger.Warning(msg)

		require.NoError(t, logger.Close())

		log, err := ioutil.ReadAll(f)
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

func TestMultipleOutputFile(t *testing.T) {
	msg := "This should get written"

	files := make([]*os.File, 0)
	options := make([]Option, 0)
	for i := 0; i < 5; i++ {
		file, err := ioutil.TempFile("", "testoutputfile")
		require.NoError(t, err)
		files = append(files, file)
		defer os.Remove(file.Name())

		options = append(options, WithOutputFile(file.Name()))
	}

	logger, err := NewLogger(options...)
	require.NoError(t, err)

	logger.Warning(msg)

	require.NoError(t, logger.Close())

	for _, file := range files {
		log, err := ioutil.ReadAll(file)
		require.NoError(t, err)
		expected := fmt.Sprintf("level=warning msg=\"%s\"", msg)
		require.Contains(t, string(log), expected)
	}
}
