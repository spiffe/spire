package fflag

import (
	"testing"

	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
)

func TestLoadOnce(t *testing.T) {
	reset()

	config := []string{}
	err := Load(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	config = append(config, "i_am_a_test_flag")
	err = Load(config)
	if err == nil {
		t.Fatal("expected an error when loading for the second time but got none")
	}

	if IsSet(FlagTestFlag) {
		t.Fatalf("expected test flag to be undisturbed after error but it was not")
	}

	reset()
}

func TestLoad(t *testing.T) {
	cases := []struct {
		name        string
		config      []string
		expectError bool
		expectSet   []Flag
		expectUnset []Flag
	}{
		{
			name:        "loads with no flags set",
			config:      []string{},
			expectError: false,
		},
		{
			name:        "loads with the test flag set",
			config:      []string{"i_am_a_test_flag"},
			expectError: false,
			expectSet:   []Flag{FlagTestFlag},
		},
		{
			name:        "does not load when bad flags are set",
			config:      []string{"non_existent_flag"},
			expectError: true,
		},
		{
			name:        "does not load when bad flags are set alongside good ones",
			config:      []string{"i_am_a_test_flag", "non_existent_flag"},
			expectError: true,
			expectUnset: []Flag{FlagTestFlag},
		},
		{
			name:        "does not change the default value",
			config:      []string{},
			expectError: false,
			expectUnset: []Flag{FlagTestFlag},
		},
	}

	for _, c := range cases {
		reset()

		t.Run(c.name, func(t *testing.T) {
			err := Load(c.config)
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

	reset()
}

func TestUnload(t *testing.T) {
	type want struct {
		errStr        string
		unloadedFlags []Flag
	}
	tests := []struct {
		name  string
		setup func()
		want  want
	}{
		{
			name: "unload without loading",
			setup: func() {
				singleton.mtx.Lock()
				defer singleton.mtx.Unlock()
				singleton.loaded = false
			},
			want: want{
				errStr: "feature flags have not been loaded",
			},
		},
		{
			name: "unload after loading",
			setup: func() {
				singleton.mtx.Lock()
				defer singleton.mtx.Unlock()
				singleton.loaded = true
				singleton.flags[FlagTestFlag] = true
			},
			want: want{
				unloadedFlags: []Flag{FlagTestFlag},
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.setup()
			err := Unload()
			if testCase.want.errStr == "" {
				assert.NoError(t, err)
			} else {
				spiretest.AssertErrorContains(t, err, testCase.want.errStr)
			}
			for _, flag := range testCase.want.unloadedFlags {
				assert.False(t, IsSet(flag))
			}
		})
	}
}

func reset() {
	singleton.mtx.Lock()
	defer singleton.mtx.Unlock()

	for k := range singleton.flags {
		singleton.flags[k] = false
	}

	singleton.loaded = false
}
