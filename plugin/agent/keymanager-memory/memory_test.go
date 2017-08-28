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
	require.NoError(t,e)
	priv, err :=x509.ParseECPrivateKey(data.PrivateKey)
	require.NoError(t,err)
	assert.Equal(t, plugin.key,priv)
}

func TestMemory_FetchPrivateKey(t *testing.T) {
	var plugin MemoryPlugin
	data, e :=plugin.GenerateKeyPair(&keymanager.GenerateKeyPairRequest{})
	require.NoError(t,err)

	priv, e := plugin.FetchPrivateKey(&keymanager.FetchPrivateKeyRequest{})
	require.NoError(t,err)
	assert.Equal(t, priv.PrivateKey, data.PrivateKey)
}

func TestMemory_Configure(t *testing.T) {
	var plugin MemoryPlugin
	data, e := plugin.Configure(&sriplugin.ConfigureRequest{})
	require.NoError(t,err)
	assert.Equal(t, &sriplugin.ConfigureResponse{}, data)

}

func TestMemory_GetPluginInfo(t *testing.T) {
	var plugin MemoryPlugin
	data, e := plugin.GetPluginInfo(&sriplugin.GetPluginInfoRequest{})
	require.NoError(t,err)
	assert.Equal(t, &sriplugin.GetPluginInfoResponse{}, data)
}
