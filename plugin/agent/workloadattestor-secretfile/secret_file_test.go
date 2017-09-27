package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/spiffe/spire/proto/agent/workloadattestor"
	spi "github.com/spiffe/spire/proto/common/plugin"
)

func TestSecretFile_Attest(t *testing.T) {
	var plugin SecretFilePlugin
	data, e := plugin.Attest(&workloadattestor.AttestRequest{})
	assert.Equal(t, &workloadattestor.AttestResponse{}, data)
	assert.Equal(t, nil, e)
}

func TestSecretFile_Configure(t *testing.T) {
	var plugin SecretFilePlugin
	data, e := plugin.Configure(&spi.ConfigureRequest{})
	assert.Equal(t, &spi.ConfigureResponse{}, data)
	assert.Equal(t, nil, e)
}

func TestSecretFile_GetPluginInfo(t *testing.T) {
	var plugin SecretFilePlugin
	data, e := plugin.GetPluginInfo(&spi.GetPluginInfoRequest{})
	assert.Equal(t, &spi.GetPluginInfoResponse{}, data)
	assert.Equal(t, nil, e)
}
