package cli

import (
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"gotest.tools/assert"
)

func TestUmask(t *testing.T) {
	if !umaskSupported {
		t.Logf("umask is not supported on this platform")
		t.Skip()
	}

	testCases := []struct {
		Initial  int
		Desired  int
		Expected int
		Logs     []string
	}{
		// Current umask is sufficient. No changes expected.
		{
			Initial: 0027, Desired: -1, Expected: 0027, Logs: nil,
		},
		// Current umask is too permissive. Set to minimum.
		{
			Initial: 0, Desired: -1, Expected: 0027, Logs: []string{
				"Current umask 0000 is too permissive; setting umask 0027.",
			},
		},
		// Current umask is too permissive. Set to minimum making sure bits
		// are OR'd.
		{
			Initial: 0125, Desired: -1, Expected: 0127, Logs: []string{
				"Current umask 0125 is too permissive; setting umask 0127.",
			},
		},
		// Desired umask is sufficient.
		{
			Initial: 0, Desired: 0027, Expected: 0027, Logs: []string{
				"Setting umask via configuration is deprecated!",
				"Setting umask 0027.",
			},
		},
		// Desired umask is too permissive. Set to minimum.
		{
			Initial: 0, Desired: 0017, Expected: 0037, Logs: []string{
				"Setting umask via configuration is deprecated!",
				"Desired umask 0017 is too permissive; setting umask 0037.",
			},
		},
		// Desired umask is too permissive. Set to minimum making sure bits
		// are OR'd.
		{
			Initial: 0, Desired: 0017, Expected: 0037, Logs: []string{
				"Setting umask via configuration is deprecated!",
				"Desired umask 0017 is too permissive; setting umask 0037.",
			},
		},
	}

	for _, testCase := range testCases {
		log, hook := test.NewNullLogger()
		t.Logf("test case: %+v", testCase)
		setUmask(testCase.Initial)
		SetUmask(log, testCase.Desired)
		actualUmask := setUmask(0022)
		assert.Equal(t, testCase.Expected, actualUmask, "umask")
		assert.DeepEqual(t, testCase.Logs, gatherLogs(hook))
	}
}

func gatherLogs(hook *test.Hook) (logs []string) {
	for _, entry := range hook.AllEntries() {
		logs = append(logs, entry.Message)
	}
	return logs
}
