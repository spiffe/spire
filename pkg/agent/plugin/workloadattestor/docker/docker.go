package docker

import (
	"context"
	"errors"
	"fmt"
	"regexp"
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
	// DockerVersion is the API version of the docker daemon. If not specified, the version is negotiated by the client.
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

	containerID, err := getContainerIDFromCGroups(p.containerIDFinder, cgroupList)
	switch {
	case err != nil:
		return nil, err
	case containerID == "":
		// Not a docker workload. Nothing more to do.
		return &workloadattestor.AttestResponse{}, nil
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
	switch {
	case config.DockerVersion != "":
		opts = append(opts, dockerclient.WithVersion(config.DockerVersion))
	default:
		opts = append(opts, dockerclient.WithAPIVersionNegotiation())
	}
	p.docker, err = dockerclient.NewClientWithOpts(opts...)
	if err != nil {
		return nil, err
	}

	switch {
	case config.CgroupPrefix != "" || config.CgroupContainerIndex != nil:
		if config.CgroupPrefix == "" || config.CgroupContainerIndex == nil {
			return nil, errors.New("cgroup_prefix and cgroup_container_index must be specified together")
		}
		p.log.Warn("cgroup_prefix and cgroup_container_index are deprecated and will be removed in a future release")

		p.containerIDFinder = &legacyContainerIDFinder{
			log:          p.log,
			cgroupPrefix: config.CgroupPrefix,
			// index 0 will always be "" as the prefix must start with /.
			// We add 1 to the requested index to hide this from the user.
			cgroupContainerIndex: *config.CgroupContainerIndex + 1,
		}
	case len(config.ContainerIDCGroupMatchers) > 0:
		p.containerIDFinder, err = cgroup.NewContainerIDFinder(config.ContainerIDCGroupMatchers)
		if err != nil {
			return nil, err
		}
	default:
		p.containerIDFinder = &defaultContainerIDFinder{}
	}

	return &spi.ConfigureResponse{}, nil
}

func (*Plugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

// getContainerIDFromCGroups returns the container ID from a set of cgroups
// using the given finder. The container ID found on each cgroup path (if any)
// must be consistent. If no container ID is found among the cgroups, i.e.,
// this isn't a docker workload, the function returns an empty string. If more
// than one container ID is found, or the "found" container ID is blank, the
// function will fail.
func getContainerIDFromCGroups(finder cgroup.ContainerIDFinder, cgroups []cgroups.Cgroup) (string, error) {
	var hasDockerEntries bool
	var containerID string
	for _, cgroup := range cgroups {
		candidate, ok := finder.FindContainerID(cgroup.GroupPath)
		if !ok {
			continue
		}

		hasDockerEntries = true

		switch {
		case containerID == "":
			// This is the first container ID found so far.
			containerID = candidate
		case containerID != candidate:
			// More than one container ID found in the cgroups.
			return "", fmt.Errorf("workloadattestor/docker: multiple container IDs found in cgroups (%s, %s)",
				containerID, candidate)
		}
	}

	switch {
	case !hasDockerEntries:
		// Not a docker workload. Since it is expected that non-docker workloads will call the
		// workload API, it is fine to return a response without any selectors.
		return "", nil
	case containerID == "":
		// The "finder" found a container ID, but it was blank. This is a
		// defensive measure against bad matcher patterns and shouldn't
		// be possible with the default finder.
		return "", errors.New("workloadattestor/docker: a pattern matched, but no container id was found")
	default:
		return containerID, nil
	}
}

type legacyContainerIDFinder struct {
	log                  hclog.Logger
	cgroupPrefix         string
	cgroupContainerIndex int
}

// FindContainerID returns the container ID from the given cgroup path. It only
// considers cgroup paths matching the configured prefix. The path is split
// into a number of slash separated segments. The container ID is assumed to
// occupy the segment at the configured index. If the cgroup path does not
// match the prefix or does not have enough segments to accommodate the index,
// the method returns false.
func (f *legacyContainerIDFinder) FindContainerID(cgroupPath string) (string, bool) {
	if !strings.HasPrefix(cgroupPath, f.cgroupPrefix) {
		return "", false
	}

	parts := strings.Split(cgroupPath, "/")

	if len(parts) <= f.cgroupContainerIndex {
		f.log.Warn("Docker entry found, but is missing the container id", telemetry.CGroupPath, cgroupPath)
		return "", false
	}

	return parts[f.cgroupContainerIndex], true
}

// dockerCGroupRE matches cgroup paths that have the following properties.
// 1) `\bdocker\b` the whole word docker
// 2) `.+` followed by one or more characters (which will start on a word boundary due to #1)
// 3) `\b([[:xdigit:]][64])\b` followed by a 64 hex-character container id on word boundary
//
// The "docker" prefix and 64-hex character container id can be anywhere in the path. The only
// requirement is that the docker prefix comes before the id.
var dockerCGroupRE = regexp.MustCompile(`\bdocker\b.+\b([[:xdigit:]]{64})\b`)

type defaultContainerIDFinder struct{}

// FindContainerID returns the container ID in the given cgroup path. The cgroup
// path must have the whole word "docker" at some point in the path followed
// at some point by a 64 hex-character container ID. If the cgroup path does
// not match the above description, the method returns false.
func (f *defaultContainerIDFinder) FindContainerID(cgroupPath string) (string, bool) {
	m := dockerCGroupRE.FindStringSubmatch(cgroupPath)
	if m != nil {
		return m[1], true
	}
	return "", false
}
