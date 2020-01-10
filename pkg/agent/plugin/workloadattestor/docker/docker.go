package docker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	dockerclient "github.com/docker/docker/client"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/agent/common/cgroups"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/docker/cgroup"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
)

const (
	pluginName         = "docker"
	subselectorLabel   = "label"
	subselectorImageID = "image_id"
	subselectorEnv     = "env"
)

var defaultContainerIDMatchers = []string{
	"/docker/<id>",
}

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, workloadattestor.PluginServer(p))
}

// Docker is a subset of the docker client functionality, useful for mocking.
type Docker interface {
	ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error)
}

type Plugin struct {
	log               hclog.Logger
	docker            Docker
	fs                cgroups.FileSystem
	mtx               *sync.RWMutex
	retryer           *retryer
	containerIDFinder cgroup.ContainerIDFinder
	findContainerID   func(string) (string, bool)

	// legacy ID extraction
	cgroupPrefix         string
	cgroupContainerIndex int
}

func New() *Plugin {
	return &Plugin{
		mtx:     &sync.RWMutex{},
		fs:      cgroups.OSFileSystem{},
		retryer: newRetryer(),
	}
}

type dockerPluginConfig struct {
	// DockerSocketPath is the location of the docker daemon socket (default: "unix:///var/run/docker.sock" on unix).
	DockerSocketPath string `hcl:"docker_socket_path"`
	// DockerVersion is the API version of the docker daemon (default: "1.40").
	DockerVersion string `hcl:"docker_version"`
	// CgroupPrefix (DEPRECATED) is the cgroup prefix to look for in the cgroup entries (default: "/docker").
	CgroupPrefix string `hcl:"cgroup_prefix"`
	// CgroupContainerIndex (DEPRECATED) is the index within the cgroup path where the container ID should be found (default: 1).
	// This is a *int to allow differentiation between the default int value (0) and the absence of the field.
	CgroupContainerIndex *int `hcl:"cgroup_container_index"`
	// ContainerIDCGroupMatchers
	ContainerIDCGroupMatchers []string `hcl:"container_id_cgroup_matchers"`
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) Attest(ctx context.Context, req *workloadattestor.AttestRequest) (*workloadattestor.AttestResponse, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	cgroupList, err := cgroups.GetCgroups(req.Pid, p.fs)
	if err != nil {
		return nil, err
	}

	var containerID string
	var hasDockerEntries bool
	for _, cgroup := range cgroupList {
		// We are only interested in cgroup entries that match our desired pattern. Example entry:
		// "10:perf_event:/docker/2235ebefd9babe0dde4df4e7c49708e24fb31fb851edea55c0ee29a18273cdf4"
		id, ok := p.findContainerID(cgroup.GroupPath)
		if !ok {
			continue
		}
		hasDockerEntries = true
		containerID = id
		break
	}

	// Not a docker workload. Since it is expected that non-docker workloads will call the
	// workload API, it is fine to return a response without any selectors.
	if !hasDockerEntries {
		return &workloadattestor.AttestResponse{}, nil
	}
	if containerID == "" {
		return nil, fmt.Errorf("workloadattestor/docker: a pattern matched, but no container id was found")
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

	return &workloadattestor.AttestResponse{
		Selectors: getSelectorsFromConfig(container.Config),
	}, nil
}

func getSelectorsFromConfig(cfg *container.Config) []*common.Selector {
	var selectors []*common.Selector
	for label, value := range cfg.Labels {
		selectors = append(selectors, &common.Selector{
			Type:  pluginName,
			Value: fmt.Sprintf("%s:%s:%s", subselectorLabel, label, value),
		})
	}
	for _, e := range cfg.Env {
		selectors = append(selectors, &common.Selector{
			Type:  pluginName,
			Value: fmt.Sprintf("%s:%s", subselectorEnv, e),
		})
	}
	if cfg.Image != "" {
		selectors = append(selectors, &common.Selector{
			Type:  pluginName,
			Value: fmt.Sprintf("%s:%s", subselectorImageID, cfg.Image),
		})
	}
	return selectors
}

func (p *Plugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	var err error
	config := &dockerPluginConfig{}
	if err = hcl.Decode(config, req.Configuration); err != nil {
		return nil, err
	}

	var opts []dockerclient.Opt
	if config.DockerSocketPath != "" {
		opts = append(opts, dockerclient.WithHost(config.DockerSocketPath))
	}
	if config.DockerVersion != "" {
		opts = append(opts, dockerclient.WithVersion(config.DockerVersion))
	}
	p.docker, err = dockerclient.NewClientWithOpts(opts...)
	if err != nil {
		return nil, err
	}

	if config.CgroupPrefix != "" || config.CgroupContainerIndex != nil {
		if config.CgroupPrefix == "" || config.CgroupContainerIndex == nil {
			return nil, errors.New("cgroup_prefix and cgroup_container_index must be specified together")
		}
		p.log.Warn("cgroup_prefix and cgroup_container_index are deprecated and will be removed in a future release")

		p.cgroupPrefix = config.CgroupPrefix
		// index 0 will always be "" as the prefix must start with /.
		// We add 1 to the requested index to hide this from the user.
		p.cgroupContainerIndex = *config.CgroupContainerIndex + 1

		p.findContainerID = p.legacyExtractID

		return &spi.ConfigureResponse{}, nil
	}

	matchers := config.ContainerIDCGroupMatchers
	if len(matchers) == 0 {
		matchers = defaultContainerIDMatchers
	}

	p.containerIDFinder, err = cgroup.NewContainerIDFinder(matchers)
	if err != nil {
		return nil, err
	}

	p.findContainerID = p.containerIDFinder.FindContainerID

	return &spi.ConfigureResponse{}, nil
}

func (*Plugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *Plugin) legacyExtractID(cgroupPath string) (string, bool) {
	if !strings.HasPrefix(cgroupPath, p.cgroupPrefix) {
		return "", false
	}

	parts := strings.Split(cgroupPath, "/")

	if len(parts) <= p.cgroupContainerIndex {
		p.log.Warn("Docker entry found, but is missing the container id", telemetry.CGroupPath, cgroupPath)
		return "", false
	}

	return parts[p.cgroupContainerIndex], true
}
