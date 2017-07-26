package aws

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAws_FetchAttestationData(t *testing.T) {
	var plugin AwsPlugin
	data, e := plugin.FetchAttestationData()
	assert.Equal(t, []byte{}, data)
	assert.Equal(t, nil, e)
}

func TestAws_Configure(t *testing.T) {
	var plugin AwsPlugin
	e := plugin.Configure("foo")
	assert.Equal(t, nil, e)
}
