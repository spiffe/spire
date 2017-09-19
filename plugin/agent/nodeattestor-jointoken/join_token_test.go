package main

import (
	"testing"

	"github.com/spiffe/spire/pkg/common"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/pkg/common/testutil"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/stretchr/testify/assert"
)

const (
	goodConfig = `{"join_token":"foobar", "trust_domain":"example.com"}`
	badConfig  = `{"trust_domain":"example.com"}`

	token    = "foobar"
	spiffeId = "spiffe://example.com/spiffe/node-id/foobar"
)

func PluginGenerator(config string) (nodeattestor.NodeAttestor, *sriplugin.ConfigureResponse, error) {
	pluginConfig := &sriplugin.ConfigureRequest{
		Configuration: config,
	}

	p := New()
	r, err := p.Configure(pluginConfig)
	return p, r, err
}

func TestJoinToken_Configure(t *testing.T) {
	assert := assert.New(t)
	_, r, err := PluginGenerator(goodConfig)
	assert.Nil(err)
	assert.Equal(&sriplugin.ConfigureResponse{}, r)
}

func TestJoinToken_FetchAttestationData_TokenPresent(t *testing.T) {
	assert := assert.New(t)

	// Build expected response
	attestationData := &common.AttestedData{
		Type: "join_token",
		Data: []byte(token),
	}
	expectedResp := &nodeattestor.FetchAttestationDataResponse{
		AttestedData: attestationData,
		SpiffeId:     spiffeId,
	}

	p, _, err := PluginGenerator(goodConfig)
	assert.Nil(err)

	resp, err := p.FetchAttestationData(&nodeattestor.FetchAttestationDataRequest{})
	assert.Nil(err)
	assert.Equal(expectedResp, resp)
}

func TestJoinToken_FetchAttestationData_TokenNotPresent(t *testing.T) {
	assert := assert.New(t)
	p, _, err := PluginGenerator(badConfig)
	assert.Nil(err)

	_, err = p.FetchAttestationData(&nodeattestor.FetchAttestationDataRequest{})
	assert.NotNil(err)
}

func TestJoinToken_GetPluginInfo(t *testing.T) {
	plugin := New()
	data, e := plugin.GetPluginInfo(&sriplugin.GetPluginInfoRequest{})
	assert.Nil(t, e)
	assert.Equal(t, &sriplugin.GetPluginInfoResponse{}, data)
}

func TestJoinToken_race(t *testing.T) {
	p := New()
	testutil.RaceTest(t, func(t *testing.T) {
		p.Configure(&sriplugin.ConfigureRequest{
			Configuration: goodConfig,
		})
		p.FetchAttestationData(&nodeattestor.FetchAttestationDataRequest{})
	})
}
