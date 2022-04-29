//go:build windows
// +build windows

package process

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"golang.org/x/sys/windows"
)

const (
	containerPrefix = `\Container_`
)

type Helper interface {
	GetContainerIDByProcess(pID int32, log hclog.Logger) (string, error)
}

func CreateHelper() Helper {
	return &helper{
		wapi: &api{},
	}
}

type helper struct {
	wapi API
}

// GetContainerIDByProcess gets the container ID from the provided process ID,
// on windows process that are running in a docker containers are grouped by Named Jobs,
// those Jobs has the container ID as name.
// In the format `\Container_${CONTAINER_ID}`
func (h *helper) GetContainerIDByProcess(pID int32, log hclog.Logger) (string, error) {
	// Search all processes that run vmcompute.exe
	vmComputeProcessIds, err := h.searchProcessByExeFile("vmcompute.exe", log)
	if err != nil {
		return "", fmt.Errorf("failed to search vmcompute process: %w", err)
	}

	// Get current process. The handle must not be closed.
	currentProcess := h.wapi.CurrentProcess()

	// Duplicate the process handle that we want to validate, with limited permissions.
	childProcessHandle, err := h.wapi.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pID))
	if err != nil {
		return "", fmt.Errorf("failed to open child process: %w", err)
	}
	defer func() {
		if err := h.wapi.CloseHandle(childProcessHandle); err != nil {
			log.Debug("Could not close child process handle", telemetry.Error, err)
		}
	}()

	handles, err := h.wapi.QuerySystemExtendedHandleInformation()
	if err != nil {
		return "", fmt.Errorf("failed to query for extended handle information: %w", err)
	}

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

		jobName, err := h.getJobName(handle, currentProcess, childProcessHandle, log)
		if err != nil {
			log.Debug("Unable to get job name", telemetry.Error, err)
			continue
		}
		if jobName != "" {
			jobNames = append(jobNames, jobName)
		}
	}

	switch len(jobNames) {
	case 0:
		return "", nil
	case 1:
		return jobNames[0][len(containerPrefix):], nil
	default:
		return "", fmt.Errorf("process has multiple jobs: %v", jobNames)
	}
}

// searchProcessByExeFile searches all the processes with specified exe file
func (h *helper) searchProcessByExeFile(exeFile string, log hclog.Logger) ([]uint32, error) {
	snapshotHandle, err := h.wapi.CreateToolhelp32Snapshot(Th32csSnapProcess, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to call CreateToolhelp32Snapshot: %w", err)
	}
	defer func() {
		if err := h.wapi.CloseHandle(snapshotHandle); err != nil {
			log.Debug("Could not close snapshot process handle", telemetry.Error, err)
		}
	}()

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := h.wapi.Process32First(snapshotHandle, &entry); err != nil {
		return nil, fmt.Errorf("failed to call Process32First: %w", err)
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
			return nil, fmt.Errorf("failed to call Process32Next: %w", err)
		}
	}

	return results, nil
}

func (h *helper) getJobName(handle SystemHandleInformationExItem, currentProcess windows.Handle, childProcessHandle windows.Handle, log hclog.Logger) (string, error) {
	// Open the handle associated with the process ID, with permissions to duplicate the handle
	hProcess, err := h.wapi.OpenProcess(windows.PROCESS_DUP_HANDLE, false, uint32(handle.UniqueProcessID))
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			// This is expected when trying to open process as a non admin user
			return "", nil
		}
		return "", fmt.Errorf("failed to open unique process: %w", err)
	}
	defer func() {
		if err := h.wapi.CloseHandle(hProcess); err != nil {
			log.Debug("Could not close process handle", telemetry.Error, err)
		}
	}()

	// Duplicate handle to get information
	var dupHandle windows.Handle
	if err := h.wapi.DuplicateHandle(hProcess, windows.Handle(handle.HandleValue), currentProcess, &dupHandle,
		0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
		if errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
			// This is expected when trying to duplicate a process that
			// is not managed by docker
			return "", nil
		}
		return "", fmt.Errorf("failed to duplicate handle: %w", err)
	}
	defer func() {
		if err := h.wapi.CloseHandle(dupHandle); err != nil {
			log.Debug("Could not close duplicated process handle", telemetry.Error, err)
		}
	}()

	typeName, err := h.wapi.GetObjectType(dupHandle)
	if err != nil {
		return "", fmt.Errorf("failed to get Object type: %w", err)
	}

	// Filter no Jobs handlers
	if typeName != "Job" {
		return "", nil
	}

	isProcessInJob := false
	if err := h.wapi.IsProcessInJob(childProcessHandle, dupHandle, &isProcessInJob); err != nil {
		return "", fmt.Errorf("failed to call IsProcessInJob: %w", err)
	}

	if !isProcessInJob {
		return "", nil
	}

	objectName, err := h.wapi.GetObjectName(dupHandle)
	if err != nil {
		return "", fmt.Errorf("failed to get object name: %w", err)
	}

	// Jobs created on windows environments start with "\Container_"
	if !strings.HasPrefix(objectName, containerPrefix) {
		return "", nil
	}
	return objectName, nil
}
