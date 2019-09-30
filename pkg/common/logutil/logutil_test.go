package logutil

import (
	"errors"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"gotest.tools/assert"
	"testing"
)

var errorLogTestCases = []struct {
	testName string
	in       string
	out      string
}{
	{
		testName: "lowercase string",
		in: "lowercase error string",
		out: "Lowercase error string",
	},
	{
		testName: "uppercase string",
		in: "Uppercase error string",
		out: "Uppercase error string",
	},
	{
		testName: "single rune string",
		in: "a",
		out: "A",
	},
	{
		testName: "empty string",
		in: "",
		out: "",
	},
	{
		testName: "UTF-8 string with non-capitalizable first rune",
		in: "今日は世界！",
		out: "今日は世界！",
	},
}

func TestErrorLogStringsAreCapitalized(t *testing.T) {
	testLogger, hook := test.NewNullLogger()
	for _, testCase := range errorLogTestCases {
		t.Run(testCase.testName, func(t *testing.T) {
			LogErrorStr(testLogger, testCase.in)
			e := hook.LastEntry()
			assert.Equal(t, logrus.ErrorLevel, e.Level)
			assert.Equal(t, testCase.out, e.Message)
		})
	}
}

func TestErrorLogsAreCapitalized(t *testing.T) {
	testLogger, hook := test.NewNullLogger()
	for _, testCase := range errorLogTestCases {
		t.Run(testCase.testName, func(t *testing.T) {
			err := errors.New(testCase.in)
			LogError(testLogger, err)
			e := hook.LastEntry()
			assert.Equal(t, logrus.ErrorLevel, e.Level)
			assert.Equal(t, testCase.out, e.Message)
		})
	}
}
