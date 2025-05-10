package errorpretty

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
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
			stdout: "failed to error\n",
			stderr: "",
		},
		{
			name:   "error_without_string_is_still_an_error",
			err:    errors.New(""),
			stdout: "an unknown error occurred\n",
			stderr: "",
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
			err := Print(c.err, stdout, stderr)

			assert.Nil(t, err)
			assert.Equal(t, c.stdout, stdout.String())
			assert.Equal(t, c.stderr, stderr.String())
		})
	}
}
