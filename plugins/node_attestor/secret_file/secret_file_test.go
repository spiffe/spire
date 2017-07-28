package secretfile

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecretFile_FetchAttestationData(t *testing.T) {
	var plugin SecretFilePlugin
	data, e := plugin.FetchAttestationData()
	assert.Equal(t, []byte{}, data)
	assert.Equal(t, nil, e)
}

func TestSecretFile_Configure(t *testing.T) {
	var plugin SecretFilePlugin
	e := plugin.Configure("foo")
	assert.Equal(t, nil, e)
}
