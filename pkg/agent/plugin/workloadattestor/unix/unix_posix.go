//go:build !windows

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
	"github.com/shirou/gopsutil/v4/process"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pluginconf"
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
	Uids() ([]uint32, error)
	Gids() ([]uint32, error)
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

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *Configuration {
	newConfig := new(Configuration)
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("failed to decode configuration: %v", err)
		return nil
	}

	return newConfig
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

func (p *Plugin) Attest(_ context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
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
			exePath, err := p.getNamespacedPath(proc)
			if err != nil {
				return nil, status.Error(codes.Internal, err.Error())
			}

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

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.config = newConfig
	p.mu.Unlock()

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
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

func (p *Plugin) getNamespacedPath(proc processInfo) (string, error) {
	if runtime.GOOS == "linux" {
		return proc.NamespacedExe(), nil
	}
	return proc.Exe()
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
