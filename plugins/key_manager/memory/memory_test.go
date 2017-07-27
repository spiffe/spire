package memory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMemory_GenerateKeyPair(t *testing.T) {
	var plugin MemoryPlugin
	data, e := plugin.GenerateKeyPair()
	assert.Equal(t, []byte{}, data)
	assert.Equal(t, nil, e)
}

func TestMemory_Configure(t *testing.T) {
	var plugin MemoryPlugin
	e := plugin.Configure("foo")
	assert.Equal(t, nil, e)
}
