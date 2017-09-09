package main

import (
	"testing"

	"github.com/spiffe/spire/pkg/agent/workloadattestor"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/stretchr/testify/assert"
)

func TestUnix_Attest(t *testing.T) {
	var plugin UnixPlugin
	data, e := plugin.Attest(&workloadattestor.AttestRequest{})
	assert.Equal(t, &workloadattestor.AttestResponse{}, data)
	assert.Equal(t, nil, e)
}

func TestUnix_Configure(t *testing.T) {
	var plugin UnixPlugin
	data, e := plugin.Configure(&sriplugin.ConfigureRequest{})
	assert.Equal(t, &sriplugin.ConfigureResponse{}, data)
	assert.Equal(t, nil, e)
}

func TestUnix_GetPluginInfo(t *testing.T) {
	var plugin UnixPlugin
	data, e := plugin.GetPluginInfo(&sriplugin.GetPluginInfoRequest{})
	assert.Equal(t, &sriplugin.GetPluginInfoResponse{}, data)
	assert.Equal(t, nil, e)
}
