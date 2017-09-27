package main

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/spiffe/spire/pkg/common/testutil"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"
)

const (
	config = `{"join_tokens":{"foo":600,"bar":1}, "trust_domain":"example.com"}`

	spiffeId = "spiffe://example.com/spiffe/node-id/foobar"
)

func AttestRequestGenerator(token string) *nodeattestor.AttestRequest {
	attestedData := &common.AttestedData{
		Type: "join_token",
		Data: []byte(token),
	}
	return &nodeattestor.AttestRequest{
		AttestedData:   attestedData,
		AttestedBefore: false,
	}
}

func TestJoinToken_Configure(t *testing.T) {
	assert := assert.New(t)

	config := `{"join_tokens":{"bar":1}, "trust_domain":"example.com"}`
	pluginConfig := &spi.ConfigureRequest{
		Configuration: config,
	}

	p := &JoinTokenPlugin{
		mtx: &sync.Mutex{},
	}
	resp, err := p.Configure(pluginConfig)
	assert.Nil(err)
	assert.Equal(&spi.ConfigureResponse{}, resp)
}

func TestJoinToken_Attest(t *testing.T) {
	assert := assert.New(t)

	config := `{"join_tokens":{"foo":600,"bar":60, "bat":1}, "trust_domain":"example.com"}`
	pluginConfig := &spi.ConfigureRequest{
		Configuration: config,
	}

	p := &JoinTokenPlugin{
		mtx: &sync.Mutex{},
	}
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
	data, e := plugin.GetPluginInfo(&spi.GetPluginInfoRequest{})
	assert.Nil(t, e)
	assert.Equal(t, &spi.GetPluginInfoResponse{}, data)
}

func TestJoinToken_race(t *testing.T) {
	p := New()
	testutil.RaceTest(t, func(t *testing.T) {
		p.Configure(&spi.ConfigureRequest{
			Configuration: config,
		})
		p.Attest(AttestRequestGenerator("foo"))
	})
}
