package unix

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/user"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/shirou/gopsutil/process"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/zeebo/errs"
)

const (
	selectorType = "unix"
)

var (
	unixErr = errs.Class("unix")
)

type processInfo interface {
	Uids() ([]int32, error)
	Gids() ([]int32, error)
	Exe() (string, error)
}

type Configuration struct {
	DiscoverWorkloadPath bool  `hcl:"discover_workload_path"`
	WorkloadSizeLimit    int64 `hcl:"workload_size_limit"`
}

type UnixPlugin struct {
	mu     sync.Mutex
	config *Configuration

	// hooks for tests
	hooks struct {
		newProcess      func(pid int32) (processInfo, error)
		lookupUserById  func(id string) (*user.User, error)
		lookupGroupById func(id string) (*user.Group, error)
	}
}

func New() *UnixPlugin {
	p := &UnixPlugin{}
	p.hooks.newProcess = func(pid int32) (processInfo, error) { return process.NewProcess(pid) }
	p.hooks.lookupUserById = user.LookupId
	p.hooks.lookupGroupById = user.LookupGroupId
	return p
}

func (p *UnixPlugin) Attest(ctx context.Context, req *workloadattestor.AttestRequest) (*workloadattestor.AttestResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	uid, err := p.getUid(req.Pid)
	if err != nil {
		return nil, err
	}

	user, err := p.getUserName(uid)
	if err != nil {
		return nil, err
	}

	gid, err := p.getGid(req.Pid)
	if err != nil {
		return nil, err
	}

	group, err := p.getGroupName(gid)
	if err != nil {
		return nil, err
	}

	// obtaining the workload process path and digest are behind a config flag
	// since it requires the agent to have permissions that might not be
	// available.
	var processPath string
	var sha256Digest string
	if config.DiscoverWorkloadPath {
		processPath, err = p.getPath(req.Pid)
		if err != nil {
			return nil, err
		}
		sha256Digest, err = getSHA256Digest(processPath, config.WorkloadSizeLimit)
		if err != nil {
			return nil, err
		}
	}

	selectors := []*common.Selector{
		makeSelector("uid", uid),
		makeSelector("user", user),
		makeSelector("gid", gid),
		makeSelector("group", group),
	}
	if processPath != "" {
		selectors = append(selectors, makeSelector("path", processPath))
	}
	if sha256Digest != "" {
		selectors = append(selectors, makeSelector("sha256", sha256Digest))
	}

	return &workloadattestor.AttestResponse{
		Selectors: selectors,
	}, nil
}

func (p *UnixPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config := new(Configuration)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, unixErr.Wrap(err)
	}
	p.setConfig(config)
	return &spi.ConfigureResponse{}, nil
}

func (p *UnixPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *UnixPlugin) getConfig() (*Configuration, error) {
	p.mu.Lock()
	config := p.config
	p.mu.Unlock()
	if config == nil {
		return nil, unixErr.New("not configured")
	}
	return config, nil
}

func (p *UnixPlugin) setConfig(config *Configuration) {
	p.mu.Lock()
	p.config = config
	p.mu.Unlock()
}

func (p *UnixPlugin) getUid(pid int32) (string, error) {
	proc, err := p.hooks.newProcess(pid)
	if err != nil {
		return "", unixErr.Wrap(err)
	}

	uids, err := proc.Uids()
	if err != nil {
		return "", unixErr.Wrap(err)
	}

	switch len(uids) {
	case 0:
		return "", unixErr.New("unable to get effective UID for PID %d", pid)
	case 1:
		return fmt.Sprint(uids[0]), nil
	default:
		return fmt.Sprint(uids[1]), nil
	}
}

func (p *UnixPlugin) getUserName(uid string) (string, error) {
	u, err := p.hooks.lookupUserById(uid)
	if err != nil {
		return "", unixErr.Wrap(err)
	}
	return u.Username, nil
}

func (p *UnixPlugin) getGid(pid int32) (string, error) {
	proc, err := p.hooks.newProcess(pid)
	if err != nil {
		return "", unixErr.Wrap(err)
	}

	gids, err := proc.Gids()
	if err != nil {
		return "", unixErr.Wrap(err)
	}

	switch len(gids) {
	case 0:
		return "", unixErr.New("unable to get effective GID for PID %d", pid)
	case 1:
		return fmt.Sprint(gids[0]), nil
	default:
		return fmt.Sprint(gids[1]), nil
	}
}

func (p *UnixPlugin) getGroupName(gid string) (string, error) {
	g, err := p.hooks.lookupGroupById(gid)
	if err != nil {
		return "", unixErr.Wrap(err)
	}
	return g.Name, nil
}

func (p *UnixPlugin) getPath(pid int32) (string, error) {
	proc, err := p.hooks.newProcess(pid)
	if err != nil {
		return "", unixErr.Wrap(err)
	}

	path, err := proc.Exe()
	if err != nil {
		return "", unixErr.Wrap(err)
	}

	return path, nil
}

func getSHA256Digest(path string, limit int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", unixErr.Wrap(err)
	}
	defer f.Close()

	if limit > 0 {
		fi, err := f.Stat()
		if err != nil {
			return "", unixErr.Wrap(err)
		}
		if fi.Size() > limit {
			return "", unixErr.New("workload %s exceeds size limit (%d > %d)", path, fi.Size(), limit)
		}
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", unixErr.Wrap(err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func makeSelector(kind, value string) *common.Selector {
	return &common.Selector{
		Type:  selectorType,
		Value: fmt.Sprintf("%s:%s", kind, value),
	}
}
