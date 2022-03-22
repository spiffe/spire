package docker

import (
	"context"
	"fmt"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	dockerclient "github.com/docker/docker/client"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
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
	ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error)
}

type Plugin struct {
	workloadattestorv1.UnsafeWorkloadAttestorServer
	configv1.UnsafeConfigServer

	log     hclog.Logger
	retryer *retryer

	mtx    sync.RWMutex
	docker Docker
	c      *containerHelper
}

func New() *Plugin {
	return &Plugin{
		retryer: newRetryer(),
	}
}

type dockerPluginConfig struct {
	// DockerSocketPath is the location of the docker daemon socket, this config can be used only on unix environments (default: "unix:///var/run/docker.sock").
	DockerSocketPath string `hcl:"docker_socket_path"`
	// DockerVersion is the API version of the docker daemon. If not specified, the version is negotiated by the client.
	DockerVersion string `hcl:"docker_version"`
	// ContainerIDCGroupMatchers is a list of patterns used to discover container IDs from cgroup entries.
	// See the documentation for cgroup.NewContainerIDFinder in the cgroup subpackage for more information. (Unix)
	ContainerIDCGroupMatchers []string `hcl:"container_id_cgroup_matchers"`
	// DockerHost is the host URI used to connect Docker API (default: "npipe:////./pipe/docker_engine").
	DockerHost string `hcl:"docker_host"`
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
	if p.c != nil {
		p.c.log = log
	}
}

func (p *Plugin) Attest(ctx context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	containerID, err := p.c.getContainerID(req.Pid)
	switch {
	case err != nil:
		return nil, err
	case containerID == "":
		// Not a docker workload. Nothing more to do.
		return &workloadattestorv1.AttestResponse{}, nil
	}

	var container types.ContainerJSON
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

	return &workloadattestorv1.AttestResponse{
		SelectorValues: getSelectorValuesFromConfig(container.Config),
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
	var err error
	config := &dockerPluginConfig{}
	if err = hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, err
	}

	if err := validateOS(config); err != nil {
		return nil, err
	}

	containerHelper, err := createHelper(config, p.log)
	if err != nil {
		return nil, err
	}

	var opts []dockerclient.Opt
	dockerHost := getDockerHost(config)
	if dockerHost != "" {
		opts = append(opts, dockerclient.WithHost(dockerHost))
	}
	switch {
	case config.DockerVersion != "":
		opts = append(opts, dockerclient.WithVersion(config.DockerVersion))
	default:
		opts = append(opts, dockerclient.WithAPIVersionNegotiation())
	}

	docker, err := dockerclient.NewClientWithOpts(opts...)
	if err != nil {
		return nil, err
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.docker = docker
	p.c = containerHelper
	return &configv1.ConfigureResponse{}, nil
}
