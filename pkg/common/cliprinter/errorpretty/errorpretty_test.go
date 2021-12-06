package errorpretty

import (
	"bytes"
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPrint(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		stdout string
		stderr string
	}{
		{
			name:   "simple_error",
			err:    errors.New("failed to error"),
			stdout: "",
			stderr: "failed to error\n",
		},
		{
			name:   "error_without_string_is_still_an_error",
			err:    errors.New(""),
			stdout: "",
			stderr: "An unknown error occurred\n",
		},
		{
			name:   "nil_is_not_an_error",
			err:    nil,
			stdout: "",
			stderr: "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stdout := &bytes.Buffer{}
			stderr := &bytes.Buffer{}
			Print(c.err, stdout, stderr)

			assert.Equal(t, c.stdout, stdout.String())
			assert.Equal(t, c.stderr, stderr.String())
		})
	}
}
