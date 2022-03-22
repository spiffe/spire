//go:build windows
// +build windows

package docker

import (
	"errors"
	"testing"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestFailToGetContainerID(t *testing.T) {
	h := &fakeProcessHelper{
		err: errors.New("oh no"),
	}

	p := newTestPlugin(
		t,
		withContainerHelper(h),
		withDocker(dockerError{}),
		withDisabledRetryer(),
	)

	selectorValues, err := doAttest(t, p)
	spiretest.RequireGRPCStatusContains(t, err, codes.Internal, "workloadattestor(docker): failed to get container ID: oh no")
	require.Empty(t, selectorValues)
}

func TestNoContainerID(t *testing.T) {
	h := &fakeProcessHelper{
		containerID: "",
	}

	p := newTestPlugin(
		t,
		withContainerHelper(h),
		withDocker(dockerError{}),
		withDisabledRetryer(),
	)

	selectorValues, err := doAttest(t, p)
	require.NoError(nil, err)
	require.Empty(t, selectorValues)
}

func TestConfigValidateOS(t *testing.T) {
	for _, tt := range []struct {
		name       string
		config     *dockerPluginConfig
		expectCode codes.Code
		expectMsj  string
	}{
		{
			name: "DockerSocketPath",
			config: &dockerPluginConfig{
				DockerSocketPath:          "socket",
				ContainerIDCGroupMatchers: []string{},
			},
			expectCode: codes.InvalidArgument,
			expectMsj:  "invalid configuration: docker_socket_path is not supported in this platform; please use docker_host instead",
		},
		{
			name: "ContainerIDCGroupMatchers is not supported",
			config: &dockerPluginConfig{
				ContainerIDCGroupMatchers: []string{"some value"},
			},
			expectCode: codes.InvalidArgument,
			expectMsj:  "invalid configuration: container_id_cgroup_matchers is not supported in this platform",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := New()

			var err error
			plugintest.Load(t, builtin(p), new(workloadattestor.V1),
				plugintest.ConfigureJSON(tt.config),
				plugintest.CaptureConfigureError(&err))

			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsj)
		})
	}
}

func verifyConfigDefault(t *testing.T, c *containerHelper) {
	require.NotNil(t, c.ph)
}

func withDefaultDataOpt() testPluginOpt {
	h := &fakeProcessHelper{
		containerID: testContainerID,
	}
	return withContainerHelper(h)
}

func withContainerHelper(h *fakeProcessHelper) testPluginOpt {
	return func(p *Plugin) {
		p.c.ph = h
	}
}

type fakeProcessHelper struct {
	err         error
	containerID string
}

func (f *fakeProcessHelper) GetContainerIDByProcess(pID int32, log hclog.Logger) (string, error) {
	if f.err != nil {
		return "", f.err
	}

	return f.containerID, nil
}
