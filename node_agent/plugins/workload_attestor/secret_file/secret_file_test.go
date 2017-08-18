package main

import (
	"testing"

	common "github.com/spiffe/sri/node_agent/plugins/common/proto"
	"github.com/spiffe/sri/node_agent/plugins/workload_attestor/proto"
	"github.com/stretchr/testify/assert"
)

func TestSecretFile_Attest(t *testing.T) {
	var plugin SecretFilePlugin
	data, e := plugin.Attest(&sri_proto.AttestRequest{})
	assert.Equal(t, &sri_proto.AttestResponse{}, data)
	assert.Equal(t, nil, e)
}

func TestSecretFile_Configure(t *testing.T) {
	var plugin SecretFilePlugin
	data, e := plugin.Configure(&common.ConfigureRequest{})
	assert.Equal(t, &common.ConfigureResponse{}, data)
	assert.Equal(t, nil, e)
}

func TestSecretFile_GetPluginInfo(t *testing.T) {
	var plugin SecretFilePlugin
	data, e := plugin.GetPluginInfo(&common.GetPluginInfoRequest{})
	assert.Equal(t, &common.GetPluginInfoResponse{}, data)
	assert.Equal(t, nil, e)
}
