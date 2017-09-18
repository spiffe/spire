package main

import (
	"os"
	"testing"

	"github.com/spiffe/spire/pkg/agent/workloadattestor"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnix_AttestValidPID(t *testing.T) {
	plugin := &UnixPlugin{}
	req := workloadattestor.AttestRequest{Pid: int32(os.Getpid())}
	resp, err := plugin.Attest(&req)
	require.NoError(t, err)
	require.NotEmpty(t, resp.Selectors)
}

func TestUnix_AttestInvalidPID(t *testing.T) {
	plugin := &UnixPlugin{}
	req := workloadattestor.AttestRequest{Pid: -1}
	resp, err := plugin.Attest(&req)
	require.Error(t, err)
	require.Empty(t, resp.Selectors)
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
