package docker

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	dockerclient "github.com/docker/docker/client"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	testContainerID = "6469646e742065787065637420616e796f6e6520746f20726561642074686973"
)

var disabledRetryer = &retryer{disabled: true}

func TestDockerSelectors(t *testing.T) {
	tests := []struct {
		desc                 string
		mockContainerLabels  map[string]string
		mockEnv              []string
		mockImageID          string
		expectSelectorValues []string
	}{
		{
			desc:                "single label; single env",
			mockContainerLabels: map[string]string{"this": "that"},
			mockEnv:             []string{"VAR=val"},
			expectSelectorValues: []string{
				"env:VAR=val",
				"label:this:that",
			},
		},
		{
			desc:                "many labels; many env",
			mockContainerLabels: map[string]string{"this": "that", "here": "there", "up": "down"},
			mockEnv:             []string{"VAR=val", "VAR2=val"},
			expectSelectorValues: []string{
				"env:VAR2=val",
				"env:VAR=val",
				"label:here:there",
				"label:this:that",
				"label:up:down",
			},
		},
		{
			desc:                 "no labels or env for container",
			mockContainerLabels:  map[string]string{},
			expectSelectorValues: nil,
		},
		{
			desc:        "image id",
			mockImageID: "my-docker-image",
			expectSelectorValues: []string{
				"image_id:my-docker-image",
			},
		},
	}

	for _, tt := range tests {
		tt := tt // alias loop variable as it is used in the closure
		t.Run(tt.desc, func(t *testing.T) {
			d := fakeContainer{
				Labels: tt.mockContainerLabels,
				Image:  tt.mockImageID,
				Env:    tt.mockEnv,
			}

			p := newTestPlugin(t, withDocker(d), withDefaultDataOpt(t))

			selectorValues, err := doAttest(t, p)
			require.NoError(t, err)

			require.Equal(t, tt.expectSelectorValues, selectorValues)
		})
	}
}

func TestDockerError(t *testing.T) {
	p := newTestPlugin(
		t,
		withDefaultDataOpt(t),
		withDocker(dockerError{}),
		withDisabledRetryer(),
	)

	selectorValues, err := doAttest(t, p)
	require.Error(t, err)
	require.Contains(t, err.Error(), "docker error")
	require.Nil(t, selectorValues)
}

func TestDockerErrorRetries(t *testing.T) {
	mockClock := clock.NewMock(t)

	p := newTestPlugin(
		t,
		withMockClock(mockClock),
		withDocker(dockerError{}),
		withDefaultDataOpt(t),
	)

	go func() {
		mockClock.WaitForAfter(time.Second, "never got call to 'after' 1")
		mockClock.Add(100 * time.Millisecond)
		mockClock.WaitForAfter(time.Second, "never got call to 'after' 2")
		mockClock.Add(200 * time.Millisecond)
		mockClock.WaitForAfter(time.Second, "never got call to 'after' 3")
		mockClock.Add(400 * time.Millisecond)
	}()

	selectorValues, err := doAttest(t, p)
	require.Error(t, err)
	require.Contains(t, err.Error(), "docker error")
	require.Nil(t, selectorValues)
}

func TestDockerErrorContextCancel(t *testing.T) {
	mockClock := clock.NewMock(t)

	p := newTestPlugin(
		t,
		withMockClock(mockClock),
		withDefaultDataOpt(t),
	)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		mockClock.WaitForAfter(time.Second, "never got call to 'after'")
		// cancel the context after the first call
		cancel()
	}()

	res, err := doAttestWithContext(ctx, t, p)
	require.Error(t, err)
	require.Contains(t, err.Error(), "context canceled")
	require.Nil(t, res)
}

func TestDockerConfig(t *testing.T) {
	for _, tt := range []struct {
		name       string
		expectCode codes.Code
		expectMsg  string
		config     string
	}{
		{
			name:   "success configuration",
			config: `docker_version = "/123/"`,
		},
		{
			name: "bad hcl",
			config: `
container_id_cgroup_matchers = [
	"/docker/"`,
			expectCode: codes.InvalidArgument,
			expectMsg:  "unable to decode configuration:",
		},
		{
			name: "unknown configuration",
			config: `
invalid1 = "/oh/"
invalid2 = "/no/"`,
			expectCode: codes.InvalidArgument,
			expectMsg:  "unknown configurations detected: invalid1,invalid2",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := New()

			var err error
			plugintest.Load(t, builtin(p), new(workloadattestor.V1),
				plugintest.Configure(tt.config),
				plugintest.CaptureConfigureError(&err))

			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsg)
		})
	}
}

func TestDockerConfigDefault(t *testing.T) {
	p := newTestPlugin(t)

	require.NotNil(t, p.docker)
	require.Equal(t, dockerclient.DefaultDockerHost, p.docker.(*dockerclient.Client).DaemonHost())
	require.Equal(t, "1.46", p.docker.(*dockerclient.Client).ClientVersion())
	verifyConfigDefault(t, p.c)
}

func doAttest(t *testing.T, p *Plugin) ([]string, error) {
	return doAttestWithContext(context.Background(), t, p)
}

func doAttestWithContext(ctx context.Context, t *testing.T, p *Plugin) ([]string, error) {
	wp := new(workloadattestor.V1)
	plugintest.Load(t, builtin(p), wp)
	selectors, err := wp.Attest(ctx, 123)
	if err != nil {
		return nil, err
	}
	var selectorValues []string
	for _, selector := range selectors {
		require.Equal(t, pluginName, selector.Type)
		selectorValues = append(selectorValues, selector.Value)
	}
	sort.Strings(selectorValues)
	return selectorValues, nil
}

func doConfigure(t *testing.T, p *Plugin, cfg string) error {
	var err error
	plugintest.Load(t, builtin(p), new(workloadattestor.V1),
		plugintest.Configure(cfg),
		plugintest.CaptureConfigureError(&err))
	return err
}

type testPluginOpt func(*Plugin)

func withDocker(docker Docker) testPluginOpt {
	return func(p *Plugin) {
		p.docker = docker
	}
}

func withMockClock(c *clock.Mock) testPluginOpt {
	return func(p *Plugin) {
		p.retryer.clock = c
	}
}

func withDisabledRetryer() testPluginOpt {
	return func(p *Plugin) {
		p.retryer = disabledRetryer
	}
}

func newTestPlugin(t *testing.T, opts ...testPluginOpt) *Plugin {
	p := New()
	err := doConfigure(t, p, defaultPluginConfig)
	require.NoError(t, err)

	for _, o := range opts {
		o(p)
	}
	return p
}

type dockerError struct{}

func (dockerError) ContainerInspect(context.Context, string) (types.ContainerJSON, error) {
	return types.ContainerJSON{}, errors.New("docker error")
}

type fakeContainer container.Config

func (f fakeContainer) ContainerInspect(_ context.Context, containerID string) (types.ContainerJSON, error) {
	if containerID != testContainerID {
		return types.ContainerJSON{}, errors.New("expected test container ID")
	}
	config := container.Config(f)
	return types.ContainerJSON{
		Config: &config,
	}, nil
}
