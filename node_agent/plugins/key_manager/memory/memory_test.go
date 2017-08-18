package main

import (
	"testing"

	common "github.com/spiffe/sri/node_agent/plugins/common/proto"
	"github.com/spiffe/sri/node_agent/plugins/key_manager/proto"
	"github.com/stretchr/testify/assert"
)

func TestMemory_GenerateKeyPair(t *testing.T) {
	var plugin MemoryPlugin
	data, e := plugin.GenerateKeyPair(&sri_proto.GenerateKeyPairRequest{})
	assert.Equal(t, &sri_proto.GenerateKeyPairResponse{}, data)
	assert.Equal(t, nil, e)
}

func TestMemory_FetchPrivateKey(t *testing.T) {
	var plugin MemoryPlugin
	data, e := plugin.FetchPrivateKey(&sri_proto.FetchPrivateKeyRequest{})
	assert.Equal(t, &sri_proto.FetchPrivateKeyResponse{}, data)
	assert.Equal(t, nil, e)
}

func TestMemory_Configure(t *testing.T) {
	var plugin MemoryPlugin
	data, e := plugin.Configure(&common.ConfigureRequest{})
	assert.Equal(t, &common.ConfigureResponse{}, data)
	assert.Equal(t, nil, e)
}

func TestMemory_GetPluginInfo(t *testing.T) {
	var plugin MemoryPlugin
	data, e := plugin.GetPluginInfo(&common.GetPluginInfoRequest{})
	assert.Equal(t, &common.GetPluginInfoResponse{}, data)
	assert.Equal(t, nil, e)
}
