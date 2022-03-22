//go:build windows
// +build windows

package docker

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"syscall"
	"unsafe"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/docker/winapi"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"golang.org/x/sys/windows"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func createHelper(c *dockerPluginConfig, log hclog.Logger) (*containerHelper, error) {
	return &containerHelper{
		wapi: winapi.CreateAPI(),
		log:  log,
	}, nil
}

type containerHelper struct {
	wapi winapi.API
	log  hclog.Logger
}

func (h *containerHelper) getContainerID(pID int32) (string, error) {
	containerID, err := h.getContainerIDByProcess(pID)
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to get container ID: %v", err)
	}
	return containerID, nil
}

// GetContainerIDByProcess get container ID from provided process ID,
// processes running in a docker containers are grouped by Job objects (https://docs.microsoft.com/en-us/windows/win32/procthread/job-objects),
// those Jobs has the container ID as name, in the format `\Container_${CONTAINER_ID}`
func (h *containerHelper) getContainerIDByProcess(pID int32) (string, error) {
	// Search all processes that runs vmcompute.exe
	vmComputeProcessIds, err := h.searchProcessByExeFile("vmcompute.exe")
	if err != nil {
		return "", fmt.Errorf("failed to search vmcompute process: %w", err)
	}

	// Get current process, current process handle is not required to be closed
	currentProcess := h.wapi.CurrentProcess()

	// Duplicate process handle we want to validate, with limited permissions
	childProcessHandle, err := h.wapi.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pID))
	if err != nil {
		return "", fmt.Errorf("failed to open child process: %w", err)
	}
	defer func() {
		if err := h.wapi.CloseHandle(childProcessHandle); err != nil {
			h.log.Warn("Could not close child process handle", telemetry.Error, err)
		}
	}()

	buffer, err := h.querySystemInformation()
	if err != nil {
		return "", err
	}

	handlesList := (*winapi.SystemExtendedHandleInformation)(unsafe.Pointer(&buffer[0]))
	handles := make([]winapi.SystemHandleInformationExItem, int(handlesList.NumberOfHandles))
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&handles))
	hdr.Data = uintptr(unsafe.Pointer(&handlesList.Handles[0]))

	// Verify if process ID is a vmcompute process
	isVmcomputeProcess := func(pID uint32) bool {
		for _, vmID := range vmComputeProcessIds {
			if pID == vmID {
				return true
			}
		}
		return false
	}

	var jobNames []string
	for _, handle := range handles {
		// Filter all handles related with vmcompute processes
		if !isVmcomputeProcess(uint32(handle.UniqueProcessID)) {
			continue
		}

		// Open handle process ID, with permissions to duplicateg handle
		hProcess, err := h.wapi.OpenProcess(windows.PROCESS_DUP_HANDLE, false, uint32(handle.UniqueProcessID))
		if err != nil {
			// TODO: may I just continue?
			// return "", fmt.Errorf("failed to open process: %v", err)
			continue
		}
		defer func() {
			if err := h.wapi.CloseHandle(hProcess); err != nil {
				h.log.Warn("Could not close process handle", telemetry.Error, err)
			}
		}()

		// Duplicate handle to get information
		var dupHandle windows.Handle
		if h.wapi.DuplicateHandle(hProcess, windows.Handle(handle.HandleValue), currentProcess, &dupHandle,
			0, true, windows.DUPLICATE_SAME_ACCESS) != nil {
			continue
		}
		defer func() {
			if err := h.wapi.CloseHandle(dupHandle); err != nil {
				h.log.Warn("Could not close duplicated process handle", telemetry.Error, err)
			}
		}()

		typeName, err := h.getObjectType(dupHandle)
		if err != nil {
			return "", err
		}

		// Filter no Jobs handlers
		if typeName != "Job" {
			continue
		}

		isProcessInJob := false
		if err := h.wapi.IsProcessInJob(childProcessHandle, dupHandle, &isProcessInJob); err != nil {
			return "", err
		}

		if !isProcessInJob {
			continue
		}

		objectName, err := h.getObjectName(dupHandle)
		if err != nil {
			return "", err
		}

		// Jobs created on windows environments start with "\Container_"
		if !strings.HasPrefix(objectName, `\Container_`) {
			continue
		}

		jobNames = append(jobNames, objectName)
	}

	if len(jobNames) > 1 {
		return "", fmt.Errorf("process has multiple jobs: %v", jobNames)
	}

	return jobNames[0][11:], nil
}

// searchProcessByExeFile search all process with specified exe file
func (h *containerHelper) searchProcessByExeFile(exeFile string) ([]uint32, error) {
	snapshotHandle, err := h.wapi.CreateToolhelp32Snapshot(winapi.Th32csSnapProcess, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := h.wapi.CloseHandle(snapshotHandle); err != nil {
			h.log.Warn("Could not close snapshot process handle", telemetry.Error, err)
		}
	}()

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := h.wapi.Process32First(snapshotHandle, &entry); err != nil {
		return nil, err
	}

	var results []uint32

	for {
		entryExeFile := syscall.UTF16ToString(entry.ExeFile[:])
		if entryExeFile == exeFile {
			results = append(results, entry.ProcessID)
		}

		if err := h.wapi.Process32Next(snapshotHandle, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return nil, err
		}
	}

	return results, nil
}

// querySystemInformation use NtQuerySystemInformation to get all handles runnig on system
func (h *containerHelper) querySystemInformation() ([]byte, error) {
	buffer := make([]byte, 1024)
	var retLen uint32
	var status windows.NTStatus

	for {
		status = h.wapi.NtQuerySystemInformation(
			windows.SystemExtendedHandleInformation,
			unsafe.Pointer(&buffer[0]),
			uint32(len(buffer)),
			&retLen,
		)

		if status == windows.STATUS_BUFFER_OVERFLOW ||
			status == windows.STATUS_BUFFER_TOO_SMALL ||
			status == windows.STATUS_INFO_LENGTH_MISMATCH {
			if int(retLen) <= cap(buffer) {
				(*reflect.SliceHeader)(unsafe.Pointer(&buffer)).Len = int(retLen)
			} else {
				buffer = make([]byte, int(retLen))
			}
			continue
		} else {
			// if no error
			if status>>30 != 3 {
				buffer = (buffer)[:int(retLen)]
				return buffer, nil
			}
			return nil, status
		}
	}
}

// getObjectType get the handle type
func (h *containerHelper) getObjectType(handle windows.Handle) (string, error) {
	buffer := make([]byte, 1024*10)
	length := uint32(0)

	status := h.wapi.NtQueryObject(handle, winapi.ObjectTypeInformationClass,
		&buffer[0], uint32(len(buffer)), &length)
	if status != windows.STATUS_SUCCESS {
		return "", status
	}

	return (*winapi.ObjectTypeInformation)(unsafe.Pointer(&buffer[0])).TypeName.String(), nil
}

// getObjectName get the handle name
func (h *containerHelper) getObjectName(handle windows.Handle) (string, error) {
	buffer := make([]byte, 1024*2)
	var length uint32

	status := h.wapi.NtQueryObject(handle, winapi.ObjectNameInformationClass,
		&buffer[0], uint32(len(buffer)), &length)
	if status != windows.STATUS_SUCCESS {
		return "", status
	}

	return (*winapi.UnicodeString)(unsafe.Pointer(&buffer[0])).String(), nil
}

func validateOS(c *dockerPluginConfig) error {
	if c.DockerSocketPath != "" {
		return status.Error(codes.InvalidArgument, "invalid configuration: docker_socket_path is not supported in this platform; please use docker_host instead")
	}

	if len(c.ContainerIDCGroupMatchers) > 0 {
		return status.Error(codes.InvalidArgument, "invalid configuration: container_id_cgroup_matchers is not supported in this platform")
	}

	return nil
}

func getDockerHost(c *dockerPluginConfig) string {
	return c.DockerHost
}
