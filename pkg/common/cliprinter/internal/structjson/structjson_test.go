package structjson

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrint(t *testing.T) {
	cases := []struct {
		name   string
		s      []any
		stdout string
		stderr string
	}{
		{
			name: "friendly_struct",
			s: []any{
				&friendlyStruct{Friendly: true},
			},
			stdout: "{\"friendly\":true}\n",
			stderr: "",
		},
		{
			name: "double_friendly_struct",
			s: []any{
				&friendlyStruct{Friendly: true},
				&friendlyStruct{Friendly: true},
			},
			stdout: "[{\"friendly\":true},{\"friendly\":true}]\n",
			stderr: "",
		},
		{
			name:   "nil_slice",
			s:      nil,
			stdout: "",
			stderr: "",
		},
		{
			name:   "nil_struct",
			s:      []any{nil},
			stdout: "null\n",
			stderr: "",
		},
		{
			name: "empty_struct",
			s: []any{
				struct{}{},
			},
			stdout: "{}\n",
			stderr: "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stdout := &bytes.Buffer{}
			stderr := &bytes.Buffer{}
			err := Print(c.s, stdout, stderr)

			assert.Nil(t, err)
			assert.Equal(t, c.stdout, stdout.String())
			assert.Equal(t, c.stderr, stderr.String())
		})
	}
}

type friendlyStruct struct {
	Friendly bool `json:"friendly"`
}
