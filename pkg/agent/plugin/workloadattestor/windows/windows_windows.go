//go:build windows
// +build windows

package windows

import (
	"context"
	"fmt"
	"sync"
	"syscall"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"golang.org/x/sys/windows"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		workloadattestorv1.WorkloadAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

func New() *Plugin {
	p := &Plugin{q: &processQuery{}}
	return p
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

	log hclog.Logger
	q   processQueryer
}

type processInfo struct {
	pid        int32
	user       string
	userSID    string
	path       string
	groups     []string
	groupsSIDs []string
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) Attest(ctx context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	process, err := p.newProcessInfo(req.Pid, config.DiscoverWorkloadPath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get process information: %v", err)
	}
	var selectorValues []string
	selectorValues = addSelectorValueIfNotEmpty(selectorValues, "user_name", process.user)
	selectorValues = addSelectorValueIfNotEmpty(selectorValues, "user_sid", process.userSID)
	for _, groupSID := range process.groupsSIDs {
		selectorValues = addSelectorValueIfNotEmpty(selectorValues, "group_sid", groupSID)
	}
	for _, group := range process.groups {
		selectorValues = addSelectorValueIfNotEmpty(selectorValues, "group_name", group)
	}

	// obtaining the workload process path and digest are behind a config flag
	// since it requires the agent to have permissions that might not be
	// available.
	if config.DiscoverWorkloadPath {
		selectorValues = append(selectorValues, makeSelectorValue("path", process.path))

		if config.WorkloadSizeLimit >= 0 {
			sha256Digest, err := util.GetSHA256Digest(process.path, config.WorkloadSizeLimit)
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

func (p *Plugin) newProcessInfo(pid int32, queryPath bool) (*processInfo, error) {
	p.log = p.log.With(telemetry.PID, pid)

	h, err := p.q.OpenProcess(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to open process: %w", err)
	}
	defer func() {
		if err := p.q.CloseHandle(h); err != nil {
			p.log.Warn("Could not close process handle", telemetry.Error, err)
		}
	}()

	// Retrieve an access token to describe the security context of
	// the process from which we obtained the handle.
	var token windows.Token
	err = p.q.OpenProcessToken(h, &token)
	if err != nil {
		return nil, fmt.Errorf("failed to open the access token associated with the process: %w", err)
	}
	defer func() {
		if err := p.q.CloseProcessToken(token); err != nil {
			p.log.Warn("Could not close access token", telemetry.Error, err)
		}
	}()

	// Get user information
	tokenUser, err := p.q.GetTokenUser(&token)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user account information from access token: %w", err)
	}

	processInfo := &processInfo{pid: pid}
	processInfo.userSID = tokenUser.User.Sid.String()
	userAccount, userDomain, err := p.q.LookupAccount(tokenUser.User.Sid)
	if err != nil {
		p.log.Warn("failed to lookup account from user SID", "sid", tokenUser.User.Sid, "error", err)
	} else {
		processInfo.user = parseAccount(userAccount, userDomain)
	}

	// Get groups information
	tokenGroups, err := p.q.GetTokenGroups(&token)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve group accounts information from access token: %w", err)
	}
	groups := p.q.AllGroups(tokenGroups)

	for _, group := range groups {
		// Each group has a set of attributes that control how
		// the system uses the SID in an access check.
		// We are interested in the SE_GROUP_ENABLED attribute.
		// https://docs.microsoft.com/en-us/windows/win32/secauthz/sid-attributes-in-an-access-token
		enabledSelector := getGroupEnabledSelector(group.Attributes)
		processInfo.groupsSIDs = append(processInfo.groupsSIDs, enabledSelector+":"+group.Sid.String())
		groupAccount, groupDomain, err := p.q.LookupAccount(group.Sid)
		if err != nil {
			p.log.Warn("failed to lookup account from group SID", "sid", group.Sid, "error", err)
			continue
		}
		// If the LookupAccount call succeeded, we know that groupAccount is not empty
		processInfo.groups = append(processInfo.groups, enabledSelector+":"+parseAccount(groupAccount, groupDomain))
	}

	if queryPath {
		if processInfo.path, err = p.q.GetProcessExe(h); err != nil {
			return nil, fmt.Errorf("error getting process exe: %w", err)
		}
	}

	return processInfo, nil
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

type processQueryer interface {
	// OpenProcess returns an open handle to the specified process id.
	OpenProcess(int32) (windows.Handle, error)

	// OpenProcessToken opens the access token associated with a process.
	OpenProcessToken(windows.Handle, *windows.Token) error

	// LookupAccount retrieves the name of the account for the specified
	// SID and the name of the first domain on which that SID is found.
	LookupAccount(sid *windows.SID) (account, domain string, err error)

	// GetTokenUser retrieves user account information of the
	// specified token.
	GetTokenUser(*windows.Token) (*windows.Tokenuser, error)

	// GetTokenGroups retrieves group accounts information of the
	// specified token.
	GetTokenGroups(*windows.Token) (*windows.Tokengroups, error)

	// AllGroups returns a slice that can be used to iterate over
	// the specified Tokengroups.
	AllGroups(*windows.Tokengroups) []windows.SIDAndAttributes

	// CloseHandle closes an open object handle.
	CloseHandle(windows.Handle) error

	// CloseProcessToken releases access to the specified access token.
	CloseProcessToken(windows.Token) error

	// GetProcessExe returns the executable file path relating to the
	// specified process handle.
	GetProcessExe(windows.Handle) (string, error)
}

type processQuery struct {
}

func (q *processQuery) OpenProcess(pid int32) (handle windows.Handle, err error) {
	return windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
}

func (q *processQuery) OpenProcessToken(h windows.Handle, token *windows.Token) (err error) {
	return windows.OpenProcessToken(h, syscall.TOKEN_QUERY, token)
}

func (q *processQuery) LookupAccount(sid *windows.SID) (account, domain string, err error) {
	account, domain, _, err = sid.LookupAccount("")
	return account, domain, err
}

func (q *processQuery) GetTokenUser(t *windows.Token) (*windows.Tokenuser, error) {
	return t.GetTokenUser()
}

func (q *processQuery) GetTokenGroups(t *windows.Token) (*windows.Tokengroups, error) {
	return t.GetTokenGroups()
}

func (q *processQuery) AllGroups(t *windows.Tokengroups) []windows.SIDAndAttributes {
	return t.AllGroups()
}

func (q *processQuery) CloseHandle(h windows.Handle) error {
	return windows.CloseHandle(h)
}

func (q *processQuery) CloseProcessToken(t windows.Token) error {
	return t.Close()
}

func (q *processQuery) GetProcessExe(h windows.Handle) (string, error) {
	buf := make([]uint16, syscall.MAX_LONG_PATH)
	size := uint32(syscall.MAX_LONG_PATH)

	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", err
	}

	return windows.UTF16ToString(buf), nil
}

func addSelectorValueIfNotEmpty(selectorValues []string, kind, value string) []string {
	if value != "" {
		return append(selectorValues, makeSelectorValue(kind, value))
	}
	return selectorValues
}

func parseAccount(account, domain string) string {
	if domain == "" {
		return account
	}
	return domain + "\\" + account
}

func getGroupEnabledSelector(attributes uint32) string {
	if attributes&windows.SE_GROUP_ENABLED != 0 {
		return "se_group_enabled:true"
	}
	return "se_group_enabled:false"
}

func makeSelectorValue(kind, value string) string {
	return fmt.Sprintf("%s:%s", kind, value)
}
