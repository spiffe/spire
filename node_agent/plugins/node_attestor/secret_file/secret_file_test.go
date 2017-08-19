package main

import (
	"testing"

	"github.com/spiffe/sri/common/plugin"
	"github.com/spiffe/sri/node_agent/plugins/node_attestor"
	"github.com/stretchr/testify/assert"
)

func TestSecretFile_FetchAttestationData(t *testing.T) {
	var plugin SecretFilePlugin
	data, e := plugin.FetchAttestationData(&nodeattestor.FetchAttestationDataRequest{})
	assert.Equal(t, &nodeattestor.FetchAttestationDataResponse{}, data)
	assert.Equal(t, nil, e)
}

func TestSecretFile_Configure(t *testing.T) {
	var plugin SecretFilePlugin
	data, e := plugin.Configure(&sriplugin.ConfigureRequest{})
	assert.Equal(t, &sriplugin.ConfigureResponse{}, data)
	assert.Equal(t, nil, e)
}

func TestSecretFile_GetPluginInfo(t *testing.T) {
	var plugin SecretFilePlugin
	data, e := plugin.GetPluginInfo(&sriplugin.GetPluginInfoRequest{})
	assert.Equal(t, &sriplugin.GetPluginInfoResponse{}, data)
	assert.Equal(t, nil, e)
}
