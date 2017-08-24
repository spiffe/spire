package main

import (
	"testing"
	"time"

	common "github.com/spiffe/sri/common/plugin"
	"github.com/spiffe/sri/control_plane/plugins/node_attestor"
	"github.com/stretchr/testify/assert"
)

const (
	config = `{"join_tokens":{"foo":600,"bar":1}, "trust_domain":"example.com"}`

	spiffeId = "spiffe://example.com/spiffe/node-id/foobar"
)

func AttestRequestGenerator(token string) *cpnodeattestor.AttestRequest {
	attestedData := &cpnodeattestor.AttestedData{
		Type: "join_token",
		Data: []byte(token),
	}
	return &cpnodeattestor.AttestRequest{
		AttestedData:   attestedData,
		AttestedBefore: false,
	}
}

func TestJoinToken_Configure(t *testing.T) {
	assert := assert.New(t)

	config := `{"join_tokens":{"bar":1}, "trust_domain":"example.com"}`
	pluginConfig := &common.ConfigureRequest{
		Configuration: config,
	}

	p := &JoinTokenPlugin{}
	resp, err := p.Configure(pluginConfig)
	assert.Nil(err)
	assert.Equal(&common.ConfigureResponse{}, resp)
}

func TestJoinToken_Attest(t *testing.T) {
	assert := assert.New(t)

	config := `{"join_tokens":{"foo":600,"bar":60, "bat":1}, "trust_domain":"example.com"}`
	pluginConfig := &common.ConfigureRequest{
		Configuration: config,
	}

	p := &JoinTokenPlugin{}
	_, err := p.Configure(pluginConfig)
	assert.Nil(err)

	// Test valid token
	request := AttestRequestGenerator("foo")
	resp, err := p.Attest(request)
	assert.Nil(err)
	assert.True(resp.Valid)

	// SPIFFE ID is well-formed
	assert.Equal(resp.BaseSPIFFEID, "spiffe://example.com/spiffe/node-id/foo")

	// Token is not re-usable
	// Token must be registered
	resp, err = p.Attest(request)
	assert.NotNil(err)
	assert.False(resp.Valid)

	// Plugin doesn't support AttestedBefore
	request = AttestRequestGenerator("bar")
	request.AttestedBefore = true
	resp, err = p.Attest(request)
	assert.NotNil(err)
	assert.False(resp.Valid)

	// Token must not be expired
	// 1s ttl on `bat`
	time.Sleep(time.Second * 1)
	request = AttestRequestGenerator("bat")
	resp, err = p.Attest(request)
	assert.NotNil(err)
	assert.False(resp.Valid)
}

func TestJoinToken_GetPluginInfo(t *testing.T) {
	var plugin JoinTokenPlugin
	data, e := plugin.GetPluginInfo(&common.GetPluginInfoRequest{})
	assert.Nil(t, e)
	assert.Equal(t, &common.GetPluginInfoResponse{}, data)
}
