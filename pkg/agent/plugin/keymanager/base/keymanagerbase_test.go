package keymanagerbase

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSetsConfigDefaults(t *testing.T) {
	// This test makes sure that we wire up the default functions
	b := New(Config{})
	assert.Equal(t, defaultGenerator{}, b.config.Generator)
	assert.Nil(t, b.config.WriteEntries)
}
