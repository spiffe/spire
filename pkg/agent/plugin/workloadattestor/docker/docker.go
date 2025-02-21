package docker

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	dockerclient "github.com/docker/docker/client"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/token"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/common/sigstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName         = "docker"
	subselectorLabel   = "label"
	subselectorImageID = "image_id"
	subselectorEnv     = "env"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		workloadattestorv1.WorkloadAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// Docker is a subset of the docker client functionality, useful for mocking.
type Docker interface {
	ContainerInspect(ctx context.Context, containerID string) (container.InspectResponse, error)
	ImageInspectWithRaw(ctx context.Context, imageID string) (image.InspectResponse, []byte, error)
}

type Plugin struct {
	workloadattestorv1.UnsafeWorkloadAttestorServer
	configv1.UnsafeConfigServer

	log     hclog.Logger
	retryer *retryer

	mtx              sync.RWMutex
	docker           Docker
	c                *containerHelper
	sigstoreVerifier sigstore.Verifier
}

func New() *Plugin {
	return &Plugin{
		retryer: newRetryer(),
	}
}

type dockerPluginConfig struct {
	OSConfig `hcl:",squash"`

	// DockerVersion is the API version of the docker daemon. If not specified, the version is negotiated by the client.
	DockerVersion string `hcl:"docker_version" json:"docker_version"`

	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`

	Experimental experimentalConfig `hcl:"experimental,omitempty" json:"experimental,omitempty"`

	containerHelper *containerHelper
	dockerOpts      []dockerclient.Opt
	sigstoreConfig  *sigstore.Config
}

type experimentalConfig struct {
	// Sigstore contains sigstore specific configs.
	Sigstore *sigstore.HCLConfig `hcl:"sigstore,omitempty"`
}

func (p *Plugin) buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *dockerPluginConfig {
	var err error
	newConfig := &dockerPluginConfig{}
	if err = hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	if len(newConfig.UnusedKeyPositions) > 0 {
		var keys []string
		for k := range newConfig.UnusedKeyPositions {
			keys = append(keys, k)
		}

		sort.Strings(keys)
		status.ReportErrorf("unknown configurations detected: %s", strings.Join(keys, ","))
	}

	newConfig.containerHelper = p.createHelper(newConfig, status)

	dockerHost := getDockerHost(newConfig)
	if dockerHost != "" {
		newConfig.dockerOpts = append(newConfig.dockerOpts, dockerclient.WithHost(dockerHost))
	}
	if newConfig.DockerVersion == "" {
		newConfig.dockerOpts = append(newConfig.dockerOpts, dockerclient.WithAPIVersionNegotiation())
	} else {
		newConfig.dockerOpts = append(newConfig.dockerOpts, dockerclient.WithVersion(newConfig.DockerVersion))
	}

	if newConfig.Experimental.Sigstore != nil {
		newConfig.sigstoreConfig = sigstore.NewConfigFromHCL(newConfig.Experimental.Sigstore, p.log)
	}

	return newConfig
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) Attest(ctx context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	containerID, err := p.c.getContainerID(req.Pid, p.log)
	switch {
	case err != nil:
		return nil, err
	case containerID == "":
		// Not a docker workload. Nothing more to do.
		return &workloadattestorv1.AttestResponse{}, nil
	}

	var container container.InspectResponse
	err = p.retryer.Retry(ctx, func() error {
		container, err = p.docker.ContainerInspect(ctx, containerID)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	selectors := getSelectorValuesFromConfig(container.Config)

	if p.sigstoreVerifier != nil {
		imageName := container.Config.Image
		imageJSON, _, err := p.docker.ImageInspectWithRaw(ctx, imageName)
		if err != nil {
			return nil, fmt.Errorf("failed to inspect image %q: %w", imageName, err)
		}

		if len(imageJSON.RepoDigests) == 0 {
			return nil, fmt.Errorf("sigstore signature verification failed: no repo digest found for image %s", imageName)
		}

		var verified bool
		// RepoDigests is a list of content-addressable digests of locally available
		// image manifests that the image is referenced from. Multiple manifests can
		// refer to the same image.
		var allErrors []string
		for _, digest := range imageJSON.RepoDigests {
			sigstoreSelectors, err := p.sigstoreVerifier.Verify(ctx, digest)
			if err != nil {
				p.log.Warn("Error verifying sigstore image signature", telemetry.ImageID, digest, telemetry.Error, err)
				allErrors = append(allErrors, fmt.Sprintf("%s %s: %v", telemetry.ImageID, digest, err))
				continue
			}
			selectors = append(selectors, sigstoreSelectors...)
			verified = true
			break
		}

		if !verified {
			return nil, fmt.Errorf("sigstore signature verification failed for image %s: %v", imageName, fmt.Sprintf("errors: %s", strings.Join(allErrors, "; ")))
		}
	}

	return &workloadattestorv1.AttestResponse{
		SelectorValues: selectors,
	}, nil
}

func getSelectorValuesFromConfig(cfg *container.Config) []string {
	var selectorValues []string
	for label, value := range cfg.Labels {
		selectorValues = append(selectorValues, fmt.Sprintf("%s:%s:%s", subselectorLabel, label, value))
	}
	for _, e := range cfg.Env {
		selectorValues = append(selectorValues, fmt.Sprintf("%s:%s", subselectorEnv, e))
	}
	if cfg.Image != "" {
		selectorValues = append(selectorValues, fmt.Sprintf("%s:%s", subselectorImageID, cfg.Image))
	}
	return selectorValues
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, p.buildConfig)
	if err != nil {
		return nil, err
	}

	docker, err := dockerclient.NewClientWithOpts(newConfig.dockerOpts...)
	if err != nil {
		return nil, err
	}

	var sigstoreVerifier sigstore.Verifier
	if newConfig.sigstoreConfig != nil {
		verifier := sigstore.NewVerifier(newConfig.sigstoreConfig)
		err = verifier.Init(ctx)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "error initializing sigstore verifier: %v", err)
		}
		sigstoreVerifier = verifier
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.docker = docker
	p.c = newConfig.containerHelper
	p.sigstoreVerifier = sigstoreVerifier

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, p.buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}
