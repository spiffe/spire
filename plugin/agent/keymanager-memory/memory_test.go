package main

import (
	"testing"
	"crypto/x509"

	"github.com/stretchr/testify/assert"

	"github.com/spiffe/sri/pkg/common/plugin"
	"github.com/spiffe/sri/pkg/agent/keymanager"
)

func TestMemory_GenerateKeyPair(t *testing.T) {
	var plugin MemoryPlugin
	data, e := plugin.GenerateKeyPair(&keymanager.GenerateKeyPairRequest{})
	assert.NoError(t,e)
	priv, err :=x509.ParseECPrivateKey(data.PrivateKey)
	assert.NoError(t,err)
	assert.Equal(t, plugin.key,priv)
	assert.NotEmpty(t,data)
}

func TestMemory_FetchPrivateKey(t *testing.T) {
	var plugin MemoryPlugin
	data, e :=plugin.GenerateKeyPair(&keymanager.GenerateKeyPairRequest{})
	priv, e := plugin.FetchPrivateKey(&keymanager.FetchPrivateKeyRequest{})
	assert.Equal(t, priv.PrivateKey, data.PrivateKey)
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
