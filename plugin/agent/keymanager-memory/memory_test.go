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
	assert.NoError(t,err)

	priv, e := plugin.FetchPrivateKey(&keymanager.FetchPrivateKeyRequest{})
	assert.NoError(t,err)
	assert.Equal(t, priv.PrivateKey, data.PrivateKey)
}

func TestMemory_Configure(t *testing.T) {
	var plugin MemoryPlugin
	data, e := plugin.Configure(&sriplugin.ConfigureRequest{})
	assert.Equal(t, &sriplugin.ConfigureResponse{}, data)
	assert.NoError(t,err)
}

func TestMemory_GetPluginInfo(t *testing.T) {
	var plugin MemoryPlugin
	data, e := plugin.GetPluginInfo(&sriplugin.GetPluginInfoRequest{})
	assert.Equal(t, &sriplugin.GetPluginInfoResponse{}, data)
	assert.NoError(t,err)
}
