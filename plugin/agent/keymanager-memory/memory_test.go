package main

import (
	"testing"

	"github.com/spiffe/sri/pkg/common/plugin"
	"github.com/spiffe/sri/pkg/agent/keymanager"
	"github.com/stretchr/testify/assert"
)

func TestMemory_GenerateKeyPair(t *testing.T) {
	var plugin MemoryPlugin
	data, e := plugin.GenerateKeyPair(&keymanager.GenerateKeyPairRequest{})
	assert.Equal(t, &keymanager.GenerateKeyPairResponse{}, data)
	assert.Equal(t, nil, e)
}

func TestMemory_FetchPrivateKey(t *testing.T) {
	var plugin MemoryPlugin
	data, e := plugin.FetchPrivateKey(&keymanager.FetchPrivateKeyRequest{})
	assert.Equal(t, &keymanager.FetchPrivateKeyResponse{}, data)
	assert.Equal(t, nil, e)
}

func TestMemory_Configure(t *testing.T) {
	var plugin MemoryPlugin
	data, e := plugin.Configure(&sriplugin.ConfigureRequest{})
	assert.Equal(t, &sriplugin.ConfigureResponse{}, data)
	assert.Equal(t, nil, e)
}

func TestMemory_GetPluginInfo(t *testing.T) {
	var plugin MemoryPlugin
	data, e := plugin.GetPluginInfo(&sriplugin.GetPluginInfoRequest{})
	assert.Equal(t, &sriplugin.GetPluginInfoResponse{}, data)
	assert.Equal(t, nil, e)
}
