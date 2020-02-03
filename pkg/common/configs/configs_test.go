package configs

import (
	"fmt"
	"os"
	"testing"

	"github.com/spiffe/spire/test/generate"
	"github.com/stretchr/testify/assert"
)

func TestGetEnv(t *testing.T) {
	// ensure it returns the environment variable value when set
	key := generate.MustGenerateHex(t)
	expected := generate.MustGenerateHex(t)
	mustSetEnv(key, expected, t)
	actual := getEnv(key)
	mustUnsetEnv(key, t)
	assert.Equal(t, actual, expected)

	// ensure it returns an empty value when unset
	key = generate.MustGenerateHex(t)
	expected = ""
	actual = getEnv(key)
	assert.Equal(t, actual, expected)
}

func TestRender(t *testing.T) {
	key := generate.MustGenerateHex(t)
	expected := generate.MustGenerateHex(t)
	text := fmt.Sprintf("{{ env \"%s\" }}", key)
	mustSetEnv(key, expected, t)
	actual, err := Render(text)
	mustUnsetEnv(key, t)
	assert.Equal(t, expected, actual)
	assert.Nil(t, err)
}

// mustSetEnv sets an environment variable or fails the test.
func mustSetEnv(key string, value string, t *testing.T) {
	err := os.Setenv(key, value)
	if err != nil {
		t.Errorf("unable to set environment variable: [%s=%s]", key, value)
	}
}

// mustUnsetEnv unsets an environment variable or fails the test.
func mustUnsetEnv(key string, t *testing.T) {
	err := os.Unsetenv(key)
	if err != nil {
		t.Errorf("unable to unset environment variable: [%s]", key)
	}
}
