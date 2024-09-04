package docker

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	dockerclient "github.com/docker/docker/client"
	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/agent/common/sigstore"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	testContainerID = "6469646e742065787065637420616e796f6e6520746f20726561642074686973"
	testImageID     = "test-image-id"
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
		name               string
		expectCode         codes.Code
		expectMsg          string
		config             string
		sigstoreConfigured bool
	}{
		{
			name:   "success configuration",
			config: `docker_version = "/123/"`,
		},
		{
			name: "sigstore configuration",
			config: `
					experimental {
    					sigstore {
        					allowed_identities = {
            					"test-issuer-1" = ["*@example.com", "subject@otherdomain.com"]
            					"test-issuer-2" = ["domain/ci.yaml@refs/tags/*"]
        					}
        					skipped_images = ["registry/image@sha256:examplehash"]
        					rekor_url = "https://test.dev"
        					ignore_sct = true
        					ignore_tlog = true
                            ignore_attestations = true
        					registry_username = "user"
        					registry_password = "pass"
    					}
			}`,
			sigstoreConfigured: true,
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

			if tt.sigstoreConfigured {
				assert.NotNil(t, p.sigstoreVerifier)
			} else {
				assert.Nil(t, p.sigstoreVerifier)
			}
		})
	}
}

func TestDockerConfigDefault(t *testing.T) {
	p := newTestPlugin(t)

	require.NotNil(t, p.docker)
	require.Equal(t, dockerclient.DefaultDockerHost, p.docker.(*dockerclient.Client).DaemonHost())
	require.Equal(t, "1.47", p.docker.(*dockerclient.Client).ClientVersion())
	verifyConfigDefault(t, p.c)
}

func TestNewConfigFromHCL(t *testing.T) {
	cases := []struct {
		name string
		hcl  *sigstore.HCLConfig
		want *sigstore.Config
	}{
		{
			name: "complete sigstore configuration",
			hcl: &sigstore.HCLConfig{
				AllowedIdentities: map[string][]string{
					"test-issuer-1": {"*@example.com", "subject@otherdomain.com"},
					"test-issuer-2": {"domain/ci.yaml@refs/tags/*"},
				},
				SkippedImages:      []string{"registry/image@sha256:examplehash"},
				RekorURL:           strPtr("https://test.dev"),
				IgnoreSCT:          boolPtr(true),
				IgnoreTlog:         boolPtr(true),
				IgnoreAttestations: boolPtr(true),
				RegistryCredentials: map[string]*sigstore.RegistryCredential{
					"registry": {
						Username: "user",
						Password: "pass",
					},
				},
			},
			want: &sigstore.Config{
				AllowedIdentities: map[string][]string{
					"test-issuer-1": {"*@example.com", "subject@otherdomain.com"},
					"test-issuer-2": {"domain/ci.yaml@refs/tags/*"},
				},
				SkippedImages:      map[string]struct{}{"registry/image@sha256:examplehash": {}},
				RekorURL:           "https://test.dev",
				IgnoreSCT:          true,
				IgnoreTlog:         true,
				IgnoreAttestations: true,
				RegistryCredentials: map[string]*sigstore.RegistryCredential{
					"registry": {
						Username: "user",
						Password: "pass",
					},
				},
				Logger: hclog.NewNullLogger(),
			},
		},
		{
			name: "empty sigstore configuration",
			hcl:  &sigstore.HCLConfig{},
			want: &sigstore.Config{
				RekorURL:           "",
				IgnoreSCT:          false,
				IgnoreTlog:         false,
				IgnoreAttestations: false,
				AllowedIdentities:  map[string][]string{},
				SkippedImages:      map[string]struct{}{},
				Logger:             hclog.NewNullLogger(),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log := hclog.NewNullLogger()
			cfg := sigstore.NewConfigFromHCL(tc.hcl, log)
			require.Equal(t, tc.want, cfg)
		})
	}
}

func TestSigstoreVerifier(t *testing.T) {
	fakeVerifier := &fakeSigstoreVerifier{
		expectedImageID: testImageID,
		selectors:       []string{"sigstore:selector"},
		err:             nil,
	}

	fakeDocker := fakeContainer{
		Labels: map[string]string{"label": "value"},
		Image:  testImageID,
		Env:    []string{"VAR=val"},
	}

	p := newTestPlugin(t, withDocker(fakeDocker), withDefaultDataOpt(t), withSigstoreVerifier(fakeVerifier))

	// Run attestation
	selectors, err := doAttest(t, p)
	require.NoError(t, err)
	expectedSelectors := []string{
		"env:VAR=val",
		"label:label:value",
		fmt.Sprintf("image_id:%s", testImageID),
		"sigstore:selector",
	}
	require.ElementsMatch(t, expectedSelectors, selectors)
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

func withSigstoreVerifier(v sigstore.Verifier) testPluginOpt {
	return func(p *Plugin) {
		p.sigstoreVerifier = v
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

func (dockerError) ImageInspectWithRaw(context.Context, string) (types.ImageInspect, []byte, error) {
	return types.ImageInspect{}, nil, errors.New("docker error")
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

func (f fakeContainer) ImageInspectWithRaw(_ context.Context, imageName string) (types.ImageInspect, []byte, error) {
	return types.ImageInspect{ID: imageName, RepoDigests: []string{testImageID}}, nil, nil
}

type fakeSigstoreVerifier struct {
	expectedImageID string
	selectors       []string
	err             error
}

func (f *fakeSigstoreVerifier) Verify(_ context.Context, imageID string) ([]string, error) {
	if imageID != f.expectedImageID {
		return nil, fmt.Errorf("unexpected image ID: %s", imageID)
	}
	return f.selectors, f.err
}

func strPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}
