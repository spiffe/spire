package cliprinter

import (
	"testing"
)

func TestStrFormatType(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name:        "a weird nonexistent type should fail",
			input:       "i'm a nonexistent type",
			expectError: true,
		},
		{
			name:  "pretty should work",
			input: "pretty",
		},
		{
			name:  "json should work",
			input: "json",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ft, err := strToFormatType(c.input)
			if err == nil {
				if c.expectError {
					t.Error("expected error but got none")
				}
			} else {
				if !c.expectError {
					t.Errorf("got unexpected error: %v", err)
				}

				return
			}

			fstr := formatTypeToStr(ft)
			if fstr == "unknown" {
				t.Fatalf("format type string %q was valid but has no corresponding type string", c.input)
			}
		})
	}
}
