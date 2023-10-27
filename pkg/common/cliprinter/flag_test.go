package cliprinter

import (
	"bytes"
	"flag"
	"testing"

	agentapi "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
)

func TestAppendFlag(t *testing.T) {
	flagCases := []struct {
		name           string
		input          []string
		extraFlags     []string
		expectedFormat formatType
		expectError    bool
	}{
		{
			name:           "defaults to pretty print when not specified",
			input:          []string{""},
			expectedFormat: pretty,
		},
		{
			name:        "requires a value",
			input:       []string{"-output"},
			expectError: true,
		},
		{
			name:        "error when setting a different value more than once",
			input:       []string{"-output", "json", "-format", "pretty"},
			extraFlags:  []string{"format"},
			expectError: true,
		},
		{
			name:           "works when setting the same value more than once",
			input:          []string{"-output", "pretty", "-format", "pretty"},
			extraFlags:     []string{"format"},
			expectedFormat: pretty,
			expectError:    false,
		},
		{
			name:        "requires a valid format",
			input:       []string{"-output", "nonexistent"},
			expectError: true,
		},
		{
			name:           "works when specifying pretty print",
			input:          []string{"-output", "pretty"},
			expectedFormat: pretty,
		},
		{
			name:           "works when specifying json",
			input:          []string{"-output", "json"},
			expectedFormat: json,
		},
		{
			name:           "input is case insensitive",
			input:          []string{"-output", "jSoN"},
			expectedFormat: json,
		},
	}

	for _, c := range flagCases {
		t.Run(c.name, func(t *testing.T) {
			var p Printer

			fs := flag.NewFlagSet("testy", flag.ContinueOnError)
			fs.SetOutput(new(bytes.Buffer))
			defaultFlagValue := AppendFlag(&p, fs, nil)
			for _, flagName := range c.extraFlags {
				fs.Var(defaultFlagValue, flagName, "")
			}
			err := fs.Parse(c.input)
			switch {
			case err == nil:
				if c.expectError {
					t.Fatal("expected an error but got none")
				}
			default:
				if !c.expectError {
					t.Fatalf("got unexpected error: %v", err)
				}

				// If we received an error and we expected it, then we're
				// done with this test case
				return
			}

			if p == nil {
				t.Fatal("printer never got set")
			}

			pp := p.(*printer)
			if pp.getFormat() != c.expectedFormat {
				t.Errorf("expected format type %q but got %q", formatTypeToStr(c.expectedFormat), formatTypeToStr(pp.getFormat()))
			}
		})
	}
}

func TestAppendFlagWithCustomPretty(t *testing.T) {
	var p Printer

	fs := flag.NewFlagSet("testy", flag.ContinueOnError)
	AppendFlagWithCustomPretty(&p, fs, nil, nil)
	err := fs.Parse([]string{""})
	if err != nil {
		t.Fatalf("error when configured with nil pretty func: %v", err)
	}

	p = nil
	fs = flag.NewFlagSet("testy", flag.ContinueOnError)
	invoked := make(chan struct{}, 1)
	cp := func(_ *commoncli.Env, _ ...any) error {
		invoked <- struct{}{}
		return nil
	}
	AppendFlagWithCustomPretty(&p, fs, nil, cp)
	err = fs.Parse([]string{"-output", "pretty"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p == nil {
		t.Fatal("unexpected error: printer not loaded")
	}

	pp := p.(*printer)
	err = pp.printError(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case <-invoked:
	default:
		t.Error("custom pretty func not correctly loaded for error printing")
	}

	err = pp.printProto(new(agentapi.CountAgentsResponse))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case <-invoked:
	default:
		t.Error("custom pretty func not correctly loaded for proto printing")
	}

	err = pp.printStruct(struct{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case <-invoked:
	default:
		t.Error("custom pretty func not correctly loaded for proto printing")
	}
}
