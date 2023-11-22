//go:build !windows

package cli

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestUmask(t *testing.T) {
	testCases := []struct {
		Initial  int
		Expected int
		Logs     []string
	}{
		// Current umask is sufficient. No changes expected.
		{
			Initial: 0o027, Expected: 0o027, Logs: nil,
		},
		// Current umask is too permissive. Set to minimum.
		{
			Initial: 0, Expected: 0o027, Logs: []string{
				"Current umask 0000 is too permissive; setting umask 0027",
			},
		},
		// Current umask is too permissive. Set to minimum making sure bits
		// are OR'd.
		{
			Initial: 0o125, Expected: 0o127, Logs: []string{
				"Current umask 0125 is too permissive; setting umask 0127",
			},
		},
	}

	for _, testCase := range testCases {
		log, hook := test.NewNullLogger()
		t.Logf("test case: %+v", testCase)
		_ = unix.Umask(testCase.Initial)
		SetUmask(log)
		actualUmask := unix.Umask(0o022)
		assert.Equal(t, testCase.Expected, actualUmask, "umask")
		assert.Empty(t, cmp.Diff(testCase.Logs, gatherLogs(hook)))
	}
}

func gatherLogs(hook *test.Hook) (logs []string) {
	for _, entry := range hook.AllEntries() {
		logs = append(logs, entry.Message)
	}
	return logs
}
