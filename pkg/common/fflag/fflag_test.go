package fflag

import (
	"sync"
	"testing"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
)

func TestLoadOnce(t *testing.T) {
	// Ensure loader is reset
	singleton.loaded = new(sync.Once)
	singleton.flags[FlagTestFlag] = false

	config := strToConfig(t, "{i_am_a_test_flag = true}")
	err := Load(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !IsSet(FlagTestFlag) {
		t.Fatal("expected test flag to be set after loading it but it was not")
	}

	config = strToConfig(t, "{i_am_a_test_flag = false}")
	err = Load(config)
	if err == nil {
		t.Fatal("expected an error when loading for the second time but got none")
	}

	if !IsSet(FlagTestFlag) {
		t.Fatalf("expected test flag to be undisturbed after error but it was not")
	}
}

func TestLoad(t *testing.T) {
	cases := []struct {
		name        string
		config      string
		preSet      []Flag
		preUnset    []Flag
		expectError bool
		expectSet   []Flag
		expectUnset []Flag
	}{
		{
			name:        "loads with no flags set",
			config:      "{}",
			expectError: false,
		},
		{
			name:        "loads with the test flag set",
			config:      "{i_am_a_test_flag = true}",
			preUnset:    []Flag{FlagTestFlag},
			expectError: false,
			expectSet:   []Flag{FlagTestFlag},
		},
		{
			name:        "does not load when bad flags are set",
			config:      "{non_existent_flag = true}",
			expectError: true,
		},
		{
			name:        "does not load when bad flags are set alongside good ones",
			config:      "{i_am_a_test_flag = true \n non_existent_flag = true}",
			preUnset:    []Flag{FlagTestFlag},
			expectError: true,
			expectUnset: []Flag{FlagTestFlag},
		},
		{
			name:        "does not load when the syntax is wrong for a real flag",
			config:      "{i_am_a_test_flag = { foo = \"bar\" } }",
			expectError: true,
		},
		{
			name:        "does not change the default value when enabled",
			config:      "{}",
			preSet:      []Flag{FlagTestFlag},
			expectError: false,
			expectSet:   []Flag{FlagTestFlag},
		},
		{
			name:        "does not change the default value when disabled",
			config:      "{}",
			preUnset:    []Flag{FlagTestFlag},
			expectError: false,
			expectUnset: []Flag{FlagTestFlag},
		},
		{
			name:        "can be used to disable features",
			config:      "{i_am_a_test_flag = false}",
			preSet:      []Flag{FlagTestFlag},
			expectError: false,
			expectUnset: []Flag{FlagTestFlag},
		},
	}

	for _, c := range cases {
		// Reset loader
		singleton.loaded = new(sync.Once)

		t.Run(c.name, func(t *testing.T) {
			for _, set := range c.preSet {
				singleton.flags[set] = true
			}

			for _, unset := range c.preUnset {
				singleton.flags[unset] = false
			}

			err := Load(strToConfig(t, c.config))
			if err != nil && !c.expectError {
				t.Errorf("unexpected error: %v", err)
			}

			if err == nil && c.expectError {
				t.Error("expected error but got none")
			}

			for _, f := range c.expectSet {
				if !IsSet(f) {
					t.Errorf("expected flag %q to be set but it was not", f)
				}
			}

			for _, f := range c.expectUnset {
				if IsSet(f) {
					t.Errorf("expected flag %q to be unset but it was set", f)
				}
			}
		})
	}
}

func strToConfig(t *testing.T, str string) RawConfig {
	raw := &struct {
		Config ast.Node `hcl:"feature_flags"`
	}{}

	err := hcl.Decode(raw, "feature_flags "+str)
	if err != nil {
		t.Fatalf("could not decode test case config string: %v", err)
	}

	return RawConfig(raw.Config)
}
