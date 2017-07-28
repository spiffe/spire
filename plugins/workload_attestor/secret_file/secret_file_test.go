package secretfile

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecretFile_Attest(t *testing.T) {
	var plugin SecretFilePlugin
	data, e := plugin.Attest(123)
	assert.Equal(t, []string{}, data)
	assert.Equal(t, nil, e)
}

func TestSecretFile_Configure(t *testing.T) {
	var plugin SecretFilePlugin
	e := plugin.Configure("foo")
	assert.Equal(t, nil, e)
}
