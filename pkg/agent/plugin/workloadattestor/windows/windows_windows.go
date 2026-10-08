//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pluginconf"
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
	p.findServicesForProcess = p.FindServicesForProcess
	return p
}

type Configuration struct {
	DiscoverWorkloadPath      bool  `hcl:"discover_workload_path"`
	WorkloadSizeLimit         int64 `hcl:"workload_size_limit"`
	DisableGroupNameSelectors bool  `hcl:"disable_group_name_selectors"`
	EnableServiceDiscovery    bool  `hcl:"enable_service_discovery"`
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

	log hclog.Logger
	q   processQueryer

	findServicesForProcess func(int32) ([]ServiceInfo, error)
}

type processInfo struct {
	pid        int32
	user       string
	userSID    string
	path       string
	groups     []string
	groupsSIDs []string
	// Services are a slice type, as windows allows shared services (e.g., svchost.exe)
	serviceNames        []string
	serviceDisplayNames []string
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) Attest(_ context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	process, err := p.newProcessInfo(req.Pid, config.DiscoverWorkloadPath, config.DisableGroupNameSelectors)
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

	for _, serviceName := range process.serviceNames {
		selectorValues = addSelectorValueIfNotEmpty(selectorValues, "service_name", serviceName)
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

	if config.EnableServiceDiscovery {
		//ignore the error here, since we don't want to fail the attestation if we can't get the service info
		serviceInfos, err := p.findServicesForProcess(req.Pid)
		if err != nil {
			p.log.Warn("Unable to discover services for process", telemetry.Error, err)
		}
		if serviceInfos != nil {
			for _, info := range serviceInfos {
				selectorValues = addSelectorValueIfNotEmpty(selectorValues, "service_name", info.ServiceName)
				selectorValues = addSelectorValueIfNotEmpty(selectorValues, "service_display_name", info.ServiceDisplayName)
			}
		}
	}

	return &workloadattestorv1.AttestResponse{
		SelectorValues: selectorValues,
	}, nil
}

// AttestReference returns Unimplemented. This plugin does not handle
// reference-based workload attestation; the host falls back to PID-based
// Attest when the reference is a WorkloadPIDReference.
func (p *Plugin) AttestReference(_ context.Context, _ *workloadattestorv1.AttestReferenceRequest) (*workloadattestorv1.AttestReferenceResponse, error) {
	return nil, status.Error(codes.Unimplemented, "AttestReference not implemented")
}

func (p *Plugin) newProcessInfo(pid int32, queryPath bool, disableGroupNames bool) (*processInfo, error) {
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

	const AllServicesSid = "S-1-5-80-0"
	const ServiceSidPrefix = "S-1-5-80-"

	start := time.Now()
	for _, group := range groups {
		// Each group has a set of attributes that control how
		// the system uses the SID in an access check.
		// We are interested in the SE_GROUP_ENABLED attribute.
		// https://docs.microsoft.com/en-us/windows/win32/secauthz/sid-attributes-in-an-access-token
		enabledSelector := getGroupEnabledSelector(group.Attributes)
		processInfo.groupsSIDs = append(processInfo.groupsSIDs, enabledSelector+":"+group.Sid.String())
		var groupAccount, groupDomain string
		if !disableGroupNames {
			groupAccount, groupDomain, err = p.q.LookupAccount(group.Sid)
			if err != nil {
				p.log.Warn("failed to lookup account from group SID", "sid", group.Sid, "error", err)
				continue
			}
			// If the LookupAccount call succeeded, we know that groupAccount is not empty
			processInfo.groups = append(processInfo.groups, enabledSelector+":"+parseAccount(groupAccount, groupDomain))
		}
		// Is this a service?
		if strings.HasPrefix(group.Sid.String(), ServiceSidPrefix) && group.Sid.String() != AllServicesSid {
			// if disableGroupNames is set, we have to do a LookupAccount call anyway to get the service name,
			// this lookup is local only, we will not force queries on an AD so this should be fine.
			if groupAccount == "" {
				groupAccount, groupDomain, err = p.q.LookupAccount(group.Sid)
				if err != nil {
					p.log.Warn("failed to lookup account from group SID", "sid", group.Sid, "error", err)
					continue
				}
			}

			var serviceName = groupAccount

			processInfo.serviceNames = append(processInfo.serviceNames, serviceName)
		}
	}
	if !disableGroupNames {
		p.log.Debug("Group account name lookups completed", "count", len(groups), "duration_ms", time.Since(start).Milliseconds())
	}

	if queryPath {
		if processInfo.path, err = p.q.GetProcessExe(h); err != nil {
			return nil, fmt.Errorf("error getting process exe: %w", err)
		}
	}

	return processInfo, nil
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = newConfig

	if newConfig.DisableGroupNameSelectors {
		p.log.Info("Group name selectors disabled; only group_sid selectors will be produced for groups")
	}

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

func (p *Plugin) FindServicesForProcess(pid int32) ([]ServiceInfo, error) {
	service, err := NewWindowsService()
	if err != nil {
		return nil, err
	}
	pidUint32, err := util.CheckedCast[uint32](pid)
	if err != nil {
		return nil, err
	}
	serviceInfos, err := service.GetServiceInfo(pidUint32)
	if err != nil {
		return nil, err
	}

	if serviceInfos != nil {
		return serviceInfos, nil
	}

	return nil, nil
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

type processQuery struct{}

func (q *processQuery) OpenProcess(pid int32) (handle windows.Handle, err error) {
	pidUint32, err := util.CheckedCast[uint32](pid)
	if err != nil {
		return 0, fmt.Errorf("invalid value for PID: %w", err)
	}
	return windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pidUint32)
}

func (q *processQuery) OpenProcessToken(h windows.Handle, token *windows.Token) (err error) {
	return windows.OpenProcessToken(h, windows.TOKEN_QUERY, token)
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
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(windows.MAX_LONG_PATH)

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

// service discovery logic

var (
	modKernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemDirectoryW = modKernel32.NewProc("GetSystemDirectoryW")
)

type WindowsService struct {
	servicesExePath string
}

type ServiceInfo struct {
	ServiceName        string
	ServiceDisplayName string
}

func NewWindowsService() (*WindowsService, error) {
	servicesExePath, err := systemServicesExePath()
	if err != nil {
		return nil, err
	}
	return &WindowsService{
		servicesExePath: filepath.Clean(servicesExePath),
	}, nil
}

func (s *WindowsService) GetServiceInfo(pid uint32) ([]ServiceInfo, error) {
	scmPid, isService, err := s.serviceGetSCMRegisteredPid(pid)
	if err != nil {
		return nil, err
	}

	if !isService {
		return nil, nil
	}

	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, fmt.Errorf("failed to open service control manager: %w", err)
	}
	defer func(handle windows.Handle) {
		_ = windows.CloseServiceHandle(handle)
	}(scm)

	var buffer [4096]byte
	var bytesNeeded uint32
	var servicesReturned uint32
	var resumeHandle uint32
	var serviceInfos []ServiceInfo

	for {
		err = windows.EnumServicesStatusEx(scm, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32, windows.SERVICE_ACTIVE, &buffer[0], uint32(len(buffer)), &bytesNeeded, &servicesReturned, &resumeHandle, nil)
		if err != nil && !errors.Is(err, syscall.ERROR_MORE_DATA) {
			return nil, fmt.Errorf("failed to enumerate services: %w", err)
		}

		if errors.Is(err, syscall.ERROR_MORE_DATA) && servicesReturned == 0 {
			return nil, fmt.Errorf("buffer too small for even a single service entry (need %d bytes)", bytesNeeded)
		}

		if servicesReturned > 0 {
			entries := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buffer[0])), int(servicesReturned))
			for _, entry := range entries {
				if entry.ServiceStatusProcess.ProcessId == scmPid {
					serviceInfos = append(serviceInfos, ServiceInfo{
						ServiceName:        windows.UTF16PtrToString(entry.ServiceName),
						ServiceDisplayName: windows.UTF16PtrToString(entry.DisplayName),
					})
				}
			}
		}

		// We are done all services are processed
		if err == nil {
			break
		}
	}

	if len(serviceInfos) == 0 {
		return nil, nil
	}

	return serviceInfos, nil
}

func (s *WindowsService) serviceGetSCMRegisteredPid(pid uint32) (uint32, bool, error) {
	processes, err := snapshotProcesses()
	if err != nil {
		return 0, false, err
	}

	currentPID := pid
	current, ok := processes[currentPID]
	if !ok {
		// Process is already gone; treat it as not being a service.
		return 0, false, nil
	}

	currentCreatedAt, err := processCreationTime(currentPID)
	if err != nil {
		return 0, false, fmt.Errorf("failed to read creation time for process %d: %w", currentPID, err)
	}

	visited := make(map[uint32]bool)
	visited[currentPID] = true
	for current.parentPID != 0 {
		parentPID := current.parentPID
		parent, ok := processes[parentPID]
		if !ok {
			// Parent process is already gone; treat it as not being a service.
			return 0, false, nil
		}
		if visited[parentPID] {
			return 0, false, fmt.Errorf("cycle detected at parentPid: %d", parentPID)
		}
		visited[parentPID] = true

		parentCreatedAt, err := processCreationTime(parentPID)
		if err != nil {
			return 0, false, fmt.Errorf("failed to read creation time for parent process %d: %w", parentPID, err)
		}
		if parentCreatedAt > currentCreatedAt {
			// Parent PID was reused; treat it as not being a service.
			return 0, false, nil
		}

		isServices, err := s.isProcessSystemServicesRoot(parentPID, parent)
		if err != nil {
			return 0, false, err
		}
		if isServices {
			return currentPID, true, nil
		}

		currentPID = parentPID
		current = parent
		currentCreatedAt = parentCreatedAt
	}

	return 0, false, nil
}

func (s *WindowsService) isProcessSystemServicesRoot(pid uint32, process processSnapshotEntry) (bool, error) {
	if !strings.EqualFold(process.exe, "services.exe") {
		return false, nil
	}

	var sessionID uint32
	if err := windows.ProcessIdToSessionId(pid, &sessionID); err != nil {
		return false, fmt.Errorf("failed to read session id for services.exe candidate pid %d: %w", pid, err)
	}
	if sessionID != 0 {
		return false, nil
	}

	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false, fmt.Errorf("failed to open services.exe candidate pid %d: %w", pid, err)
	}
	defer func(handle windows.Handle) {
		_ = windows.CloseHandle(handle)
	}(handle)

	imagePath, err := getAbsoluteExePath(handle)
	if err != nil {
		return false, fmt.Errorf("failed to read image path for services.exe candidate pid %d: %w", pid, err)
	}

	return strings.EqualFold(filepath.Clean(imagePath), s.servicesExePath), nil
}

func systemServicesExePath() (string, error) {
	// This is the default, in the unlikely event that this is not enough we try again with MAX_LONG_PATH
	bufferSize := uint32(len("c:\\windows\\system32")) + 1
	buffer := make([]uint16, bufferSize)
	length, _, err := procGetSystemDirectoryW.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(bufferSize),
	)

	if length != 0 && length <= uintptr(bufferSize) {
		return filepath.Join(windows.UTF16ToString(buffer[:length]), "services.exe"), nil
	}

	// We are now in the very very unlikely case that windows is not installed in c:\windows\

	bufferSize = uint32(windows.MAX_LONG_PATH)
	buffer = make([]uint16, bufferSize)
	length, _, err = procGetSystemDirectoryW.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(bufferSize),
	)
	if length == 0 {
		return "", fmt.Errorf("GetSystemDirectoryW failed: %w", err)
	}
	if length < uintptr(bufferSize) {
		return filepath.Join(windows.UTF16ToString(buffer[:length]), "services.exe"), nil
	}

	return "", fmt.Errorf("GetSystemDirectoryW returned buffer size %d", length)
}

func getAbsoluteExePath(process windows.Handle) (string, error) {
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(windows.MAX_LONG_PATH)
	err := windows.QueryFullProcessImageName(process, 0, &buffer[0], &size)
	if err != nil {
		return "", err
	}
	return windows.UTF16ToString(buffer[:size]), nil
}

type processSnapshotEntry struct {
	parentPID uint32
	exe       string
}

func snapshotProcesses() (map[uint32]processSnapshotEntry, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create process snapshot: %w", err)
	}
	defer func(handle windows.Handle) {
		_ = windows.CloseHandle(handle)
	}(snapshot)

	processes := make(map[uint32]processSnapshotEntry)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil, fmt.Errorf("failed to read first process snapshot entry: %w", err)
	}
	for {
		exe := windows.UTF16ToString(entry.ExeFile[:])

		processes[entry.ProcessID] = processSnapshotEntry{
			parentPID: entry.ParentProcessID,
			exe:       exe,
		}

		err := windows.Process32Next(snapshot, &entry)

		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("failed to read process snapshot entry: %w", err)
		}
	}

	return processes, nil
}

func processCreationTime(pid uint32) (uint64, error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, err
	}
	defer func(handle windows.Handle) {
		_ = windows.CloseHandle(handle)
	}(process)

	var createdAt, exitedAt, kernelTime, userTime windows.Filetime
	if err := windows.GetProcessTimes(process, &createdAt, &exitedAt, &kernelTime, &userTime); err != nil {
		return 0, err
	}

	return uint64(createdAt.HighDateTime)<<32 | uint64(createdAt.LowDateTime), nil
}
