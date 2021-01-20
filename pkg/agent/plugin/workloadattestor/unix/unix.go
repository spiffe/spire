package unix

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/shirou/gopsutil/process"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/zeebo/errs"
)

const (
	pluginName = "unix"
)

var (
	unixErr = errs.Class("unix")
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, workloadattestor.PluginServer(p))
}

type processInfo interface {
	Uids() ([]int32, error)
	Gids() ([]int32, error)
	Groups() ([]string, error)
	Exe() (string, error)
	NamespacedExe() string
}

type PSProcessInfo struct {
	*process.Process
}

func (ps PSProcessInfo) NamespacedExe() string {
	return getProcPath(ps.Pid, "exe")
}

// Groups returns the supplementary group IDs
// This is a custom implementation that only works for linux until the next issue is fixed
// https://github.com/shirou/gopsutil/issues/913
func (ps PSProcessInfo) Groups() ([]string, error) {
	if runtime.GOOS != "linux" {
		return []string{}, nil
	}

	statusPath := getProcPath(ps.Pid, "status")

	f, err := os.Open(statusPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scnr := bufio.NewScanner(f)
	for scnr.Scan() {
		row := scnr.Text()
		parts := strings.SplitN(row, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(parts[0]))
		if key == "groups" {
			value := strings.TrimSpace(parts[1])
			return strings.Fields(value), nil
		}
	}

	if err := scnr.Err(); err != nil {
		return nil, err
	}

	return []string{}, nil
}

type Configuration struct {
	DiscoverWorkloadPath bool  `hcl:"discover_workload_path"`
	WorkloadSizeLimit    int64 `hcl:"workload_size_limit"`
}

type Plugin struct {
	workloadattestor.UnsafeWorkloadAttestorServer

	mu     sync.Mutex
	config *Configuration
	log    hclog.Logger

	// hooks for tests
	hooks struct {
		newProcess      func(pid int32) (processInfo, error)
		lookupUserByID  func(id string) (*user.User, error)
		lookupGroupByID func(id string) (*user.Group, error)
	}
}

func New() *Plugin {
	p := &Plugin{}
	p.hooks.newProcess = func(pid int32) (processInfo, error) { p, err := process.NewProcess(pid); return PSProcessInfo{p}, err }
	p.hooks.lookupUserByID = user.LookupId
	p.hooks.lookupGroupByID = user.LookupGroupId
	return p
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) Attest(ctx context.Context, req *workloadattestor.AttestRequest) (*workloadattestor.AttestResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	proc, err := p.hooks.newProcess(req.Pid)
	if err != nil {
		return nil, unixErr.New("getting process: %v", err)
	}

	var selectors []*common.Selector

	uid, err := p.getUID(proc)
	if err != nil {
		return nil, err
	}
	selectors = append(selectors, makeSelector("uid", uid))

	if user, ok := p.getUserName(uid); ok {
		selectors = append(selectors, makeSelector("user", user))
	}

	gid, err := p.getGID(proc)
	if err != nil {
		return nil, err
	}
	selectors = append(selectors, makeSelector("gid", gid))

	if group, ok := p.getGroupName(gid); ok {
		selectors = append(selectors, makeSelector("group", group))
	}

	sgIDs, err := proc.Groups()
	if err != nil {
		return nil, unixErr.New("supplementary GIDs lookup: %v", err)
	}

	for _, sgID := range sgIDs {
		selectors = append(selectors, makeSelector("supplementary_gid", sgID))

		if sGroup, ok := p.getGroupName(sgID); ok {
			selectors = append(selectors, makeSelector("supplementary_group", sGroup))
		}
	}

	// obtaining the workload process path and digest are behind a config flag
	// since it requires the agent to have permissions that might not be
	// available.
	if config.DiscoverWorkloadPath {
		processPath, err := p.getPath(proc)
		if err != nil {
			return nil, err
		}
		selectors = append(selectors, makeSelector("path", processPath))

		if config.WorkloadSizeLimit >= 0 {
			exePath := p.getNamespacedPath(proc)
			sha256Digest, err := getSHA256Digest(exePath, config.WorkloadSizeLimit)
			if err != nil {
				return nil, err
			}

			selectors = append(selectors, makeSelector("sha256", sha256Digest))
		}
	}

	return &workloadattestor.AttestResponse{
		Selectors: selectors,
	}, nil
}

func (p *Plugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config := new(Configuration)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, unixErr.Wrap(err)
	}
	p.setConfig(config)
	return &spi.ConfigureResponse{}, nil
}

func (p *Plugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *Plugin) getConfig() (*Configuration, error) {
	p.mu.Lock()
	config := p.config
	p.mu.Unlock()
	if config == nil {
		return nil, unixErr.New("not configured")
	}
	return config, nil
}

func (p *Plugin) setConfig(config *Configuration) {
	p.mu.Lock()
	p.config = config
	p.mu.Unlock()
}

func (p *Plugin) getUID(proc processInfo) (string, error) {
	uids, err := proc.Uids()
	if err != nil {
		return "", unixErr.New("UIDs lookup: %v", err)
	}

	switch len(uids) {
	case 0:
		return "", unixErr.New("UIDs lookup: no UIDs for process")
	case 1:
		return fmt.Sprint(uids[0]), nil
	default:
		return fmt.Sprint(uids[1]), nil
	}
}

func (p *Plugin) getUserName(uid string) (string, bool) {
	u, err := p.hooks.lookupUserByID(uid)
	if err != nil {
		p.log.Warn("Failed to lookup user name by uid", "uid", uid, "error", err)
		return "", false
	}
	return u.Username, true
}

func (p *Plugin) getGID(proc processInfo) (string, error) {
	gids, err := proc.Gids()
	if err != nil {
		return "", unixErr.New("GIDs lookup: %v", err)
	}

	switch len(gids) {
	case 0:
		return "", unixErr.New("GIDs lookup: no GIDs for process")
	case 1:
		return fmt.Sprint(gids[0]), nil
	default:
		return fmt.Sprint(gids[1]), nil
	}
}

func (p *Plugin) getGroupName(gid string) (string, bool) {
	g, err := p.hooks.lookupGroupByID(gid)
	if err != nil {
		p.log.Warn("Failed to lookup group name by gid", "gid", gid, "error", err)
		return "", false
	}
	return g.Name, true
}

func (p *Plugin) getPath(proc processInfo) (string, error) {
	path, err := proc.Exe()
	if err != nil {
		return "", unixErr.New("path lookup: %v", err)
	}

	return path, nil
}

func (p *Plugin) getNamespacedPath(proc processInfo) string {
	return proc.NamespacedExe()
}

func getSHA256Digest(path string, limit int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", unixErr.New("SHA256 digest: %v", err)
	}
	defer f.Close()

	if limit > 0 {
		fi, err := f.Stat()
		if err != nil {
			return "", unixErr.New("SHA256 digest: %v", err)
		}
		if fi.Size() > limit {
			return "", unixErr.New("SHA256 digest: workload %s exceeds size limit (%d > %d)", path, fi.Size(), limit)
		}
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", unixErr.New("SHA256 digest: %v", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func makeSelector(kind, value string) *common.Selector {
	return &common.Selector{
		Type:  pluginName,
		Value: fmt.Sprintf("%s:%s", kind, value),
	}
}

func getProcPath(pID int32, lastPath string) string {
	procPath := os.Getenv("HOST_PROC")
	if procPath == "" {
		procPath = "/proc"
	}
	return filepath.Join(procPath, strconv.FormatInt(int64(pID), 10), lastPath)
}
