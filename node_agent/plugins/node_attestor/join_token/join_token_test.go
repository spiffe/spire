package main

import (
	"testing"

	common "github.com/spiffe/sri/common/plugin"
	"github.com/spiffe/sri/node_agent/plugins/node_attestor"
	"github.com/stretchr/testify/assert"
)

const (
	goodConfig = `{"join_token":"foobar", "trust_domain":"example.com"}`
	badConfig  = `{"trust_domain":"example.com"}`

	token    = "foobar"
	spiffeId = "spiffe://example.com/spiffe/node-id/foobar"
)

func TestJoinToken_Configure(t *testing.T) {
	pluginConfig := &common.ConfigureRequest{
		Configuration: goodConfig,
	}

	plugin := &JoinTokenPlugin{}
	res, err := plugin.Configure(pluginConfig)
	assert.Nil(t, err)
	assert.Equal(t, &common.ConfigureResponse{}, res)
}

func TestJoinToken_FetchAttestationData(t *testing.T) {
	assert := assert.New(t)

	// Build plugin config and expected response
	pluginConfig := &common.ConfigureRequest{
		Configuration: goodConfig,
	}
	attestationData := &nodeattestor.AttestedData{
		Type: "join_token",
		Data: []byte(token),
	}
	expectedResp := &nodeattestor.FetchAttestationDataResponse{
		AttestedData: attestationData,
		SpiffeId:     spiffeId,
	}

	plugin := JoinTokenPlugin{}
	plugin.Configure(pluginConfig)
	resp, err := plugin.FetchAttestationData(&nodeattestor.FetchAttestationDataRequest{})
	assert.Nil(err)
	assert.Equal(expectedResp, resp)

	// Re-configure the plugin with a missing token
	pluginConfig = &common.ConfigureRequest{
		Configuration: badConfig,
	}
	plugin.Configure(pluginConfig)
	_, err = plugin.FetchAttestationData(&nodeattestor.FetchAttestationDataRequest{})
	assert.NotNil(err)
}

func TestJoinToken_GetPluginInfo(t *testing.T) {
	var plugin JoinTokenPlugin
	data, e := plugin.GetPluginInfo(&common.GetPluginInfoRequest{})
	assert.Nil(t, e)
	assert.Equal(t, &common.GetPluginInfoResponse{}, data)
}
