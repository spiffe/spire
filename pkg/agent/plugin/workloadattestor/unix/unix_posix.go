//go:build !windows
// +build !windows

package unix

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/shirou/gopsutil/v3/process"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		workloadattestorv1.WorkloadAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
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
	workloadattestorv1.UnsafeWorkloadAttestorServer
	configv1.UnsafeConfigServer

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

func (p *Plugin) Attest(ctx context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	proc, err := p.hooks.newProcess(req.Pid)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get process: %v", err)
	}

	var selectorValues []string

	uid, err := p.getUID(proc)
	if err != nil {
		return nil, err
	}
	selectorValues = append(selectorValues, makeSelectorValue("uid", uid))

	if user, ok := p.getUserName(uid); ok {
		selectorValues = append(selectorValues, makeSelectorValue("user", user))
	}

	gid, err := p.getGID(proc)
	if err != nil {
		return nil, err
	}
	selectorValues = append(selectorValues, makeSelectorValue("gid", gid))

	if group, ok := p.getGroupName(gid); ok {
		selectorValues = append(selectorValues, makeSelectorValue("group", group))
	}

	sgIDs, err := proc.Groups()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "supplementary GIDs lookup: %v", err)
	}

	for _, sgID := range sgIDs {
		selectorValues = append(selectorValues, makeSelectorValue("supplementary_gid", sgID))

		if sGroup, ok := p.getGroupName(sgID); ok {
			selectorValues = append(selectorValues, makeSelectorValue("supplementary_group", sGroup))
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
		selectorValues = append(selectorValues, makeSelectorValue("path", processPath))

		if config.WorkloadSizeLimit >= 0 {
			exePath := p.getNamespacedPath(proc)
			sha256Digest, err := util.GetSHA256Digest(exePath, config.WorkloadSizeLimit)
			if err != nil {
				return nil, status.Error(codes.Internal, err.Error())
			}

			selectorValues = append(selectorValues, makeSelectorValue("sha256", sha256Digest))
		}
	}

	return &workloadattestorv1.AttestResponse{
		SelectorValues: selectorValues,
	}, nil
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(Configuration)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}
	p.setConfig(config)
	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) getConfig() (*Configuration, error) {
	p.mu.Lock()
	config := p.config
	p.mu.Unlock()
	if config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
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
		return "", status.Errorf(codes.Internal, "UIDs lookup: %v", err)
	}

	switch len(uids) {
	case 0:
		return "", status.Error(codes.Internal, "UIDs lookup: no UIDs for process")
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
		return "", status.Errorf(codes.Internal, "GIDs lookup: %v", err)
	}

	switch len(gids) {
	case 0:
		return "", status.Error(codes.Internal, "GIDs lookup: no GIDs for process")
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
		return "", status.Errorf(codes.Internal, "path lookup: %v", err)
	}

	return path, nil
}

func (p *Plugin) getNamespacedPath(proc processInfo) string {
	return proc.NamespacedExe()
}

func makeSelectorValue(kind, value string) string {
	return fmt.Sprintf("%s:%s", kind, value)
}

func getProcPath(pID int32, lastPath string) string {
	procPath := os.Getenv("HOST_PROC")
	if procPath == "" {
		procPath = "/proc"
	}
	return filepath.Join(procPath, strconv.FormatInt(int64(pID), 10), lastPath)
}
