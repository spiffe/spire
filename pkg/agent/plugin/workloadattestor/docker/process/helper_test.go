//go:build windows
// +build windows

package process

import (
	"errors"
	"fmt"
	"syscall"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestGetContainerIDByProcess(t *testing.T) {
	for _, tt := range []struct {
		name            string
		api             func(t *testing.T) *fakeWinAPI
		containerID     string
		expectDebugLogs []string
		expectErr       string
	}{
		{
			name:        "success",
			api:         createDefaultFakeWinAPI,
			containerID: "ABC123",
		},
		{
			name: "multiple jobs in different process",
			api: func(t *testing.T) *fakeWinAPI {
				fAPI := createDefaultFakeWinAPI(t)
				fAPI.queryHandleInformation = append(fAPI.queryHandleInformation, SystemHandleInformationExItem{
					UniqueProcessID: 3,
					HandleValue:     uintptr(555),
				})
				fAPI.duplicateHandleResp[555] = 5551
				fAPI.getObjectTypeResp[5551] = "Job"
				fAPI.isProcessInJobMap[5551] = false
				fAPI.getObjectNameResp[5551] = `\Container_ABC123`

				return fAPI
			},
			containerID: "ABC123",
		},
		{
			name: "multiple jobs in same process but not container",
			api: func(t *testing.T) *fakeWinAPI {
				fAPI := createDefaultFakeWinAPI(t)
				fAPI.queryHandleInformation = append(fAPI.queryHandleInformation, SystemHandleInformationExItem{
					UniqueProcessID: 3,
					HandleValue:     uintptr(555),
				})
				fAPI.duplicateHandleResp[555] = 5551
				fAPI.getObjectTypeResp[5551] = "Job"
				fAPI.isProcessInJobMap[5551] = true
				fAPI.getObjectNameResp[5551] = `namedJob1`

				return fAPI
			},
			containerID: "ABC123",
		},
		{
			name: "multiple container jobs in same process",
			api: func(t *testing.T) *fakeWinAPI {
				fAPI := createDefaultFakeWinAPI(t)
				fAPI.queryHandleInformation = append(fAPI.queryHandleInformation, SystemHandleInformationExItem{
					UniqueProcessID: 3,
					HandleValue:     uintptr(555),
				})
				fAPI.duplicateHandleResp[555] = 5551
				fAPI.getObjectTypeResp[5551] = "Job"
				fAPI.isProcessInJobMap[5551] = true
				fAPI.getObjectNameResp[5551] = `\Container_XYZ789`

				return fAPI
			},
			containerID: "",
			expectErr:   "process has multiple jobs: [\\Container_ABC123 \\Container_XYZ789]",
		},
		{
			name: "could not open unique process",
			api: func(t *testing.T) *fakeWinAPI {
				fAPI := createDefaultFakeWinAPI(t)
				fAPI.openProcessPIDs = []uint32{
					123,
				}
				fAPI.queryHandleInformation = []SystemHandleInformationExItem{
					{
						UniqueProcessID: 3,
						HandleValue:     uintptr(456),
					},
				}

				return fAPI
			},
			expectDebugLogs: []string{
				"Unable to get job name: [error failed to open unique process: The system cannot find the file specified.]",
			},
			containerID: "",
		},
		{
			name: "failed to duplicate process",
			api: func(t *testing.T) *fakeWinAPI {
				fAPI := createDefaultFakeWinAPI(t)
				fAPI.queryHandleInformation = []SystemHandleInformationExItem{
					{
						UniqueProcessID: 3,
						HandleValue:     uintptr(456),
					},
				}
				fAPI.duplicateHandleErr = windows.ERROR_FILE_NOT_FOUND

				return fAPI
			},
			expectDebugLogs: []string{
				"Unable to get job name: [error failed to duplicate handle: The system cannot find the file specified.]",
			},
			containerID: "",
		},
		{
			name: "failed to duplicate process with invalid request",
			api: func(t *testing.T) *fakeWinAPI {
				fAPI := createDefaultFakeWinAPI(t)
				fAPI.queryHandleInformation = []SystemHandleInformationExItem{
					{
						UniqueProcessID: 3,
						HandleValue:     uintptr(456),
					},
				}
				fAPI.duplicateHandleErr = windows.ERROR_NOT_SUPPORTED

				return fAPI
			},
			containerID: "",
		},
		{
			name: "failed to get object type",
			api: func(t *testing.T) *fakeWinAPI {
				fAPI := createDefaultFakeWinAPI(t)
				fAPI.getObjectTypeResp = map[int32]string{
					4561: "Handle",
				}

				return fAPI
			},
			expectDebugLogs: []string{
				"Unable to get job name: [error failed to get Object type: The system cannot find the file specified.]",
			},
			containerID: "",
		},
		{
			name: "failed to call is process in job",
			api: func(t *testing.T) *fakeWinAPI {
				fAPI := createDefaultFakeWinAPI(t)
				fAPI.isProcessInJobErr = errors.New("oh no")
				return fAPI
			},
			expectDebugLogs: []string{
				"Unable to get job name: [error failed to call IsProcessInJob: oh no]",
			},
			containerID: "",
		},
		{
			name: "failed to get object name",
			api: func(t *testing.T) *fakeWinAPI {
				fAPI := createDefaultFakeWinAPI(t)
				fAPI.getObjectNameResp = map[int32]string{}
				return fAPI
			},
			expectDebugLogs: []string{
				"Unable to get job name: [error failed to get object name: The system cannot find the file specified.]",
			},
			containerID: "",
		},
		{
			name: "failed to create snapshot handle",
			api: func(t *testing.T) *fakeWinAPI {
				fAPI := createDefaultFakeWinAPI(t)
				fAPI.createSnapshotErr = windows.ERROR_ACCESS_DENIED

				return fAPI
			},
			expectErr: "failed to search vmcompute process: failed to call CreateToolhelp32Snapshot: Access is denied.",
		},
		{
			name: "failed to Process First",
			api: func(t *testing.T) *fakeWinAPI {
				fAPI := createDefaultFakeWinAPI(t)
				fAPI.process32FirstErr = windows.ERROR_ACCESS_DENIED

				return fAPI
			},
			expectErr: "failed to search vmcompute process: failed to call Process32First: Access is denied.",
		},
		{
			name: "failed to Process next",
			api: func(t *testing.T) *fakeWinAPI {
				fAPI := createDefaultFakeWinAPI(t)
				fAPI.process32NextEntryErr = windows.ERROR_ACCESS_DENIED

				return fAPI
			},
			expectErr: "failed to search vmcompute process: failed to call Process32Next: Access is denied.",
		},
		{
			name: "failed to open child process",
			api: func(t *testing.T) *fakeWinAPI {
				fAPI := createDefaultFakeWinAPI(t)
				fAPI.openProcessPIDs = []uint32{
					3,
				}

				return fAPI
			},
			expectErr: "failed to open child process: The system cannot find the file specified.",
		},
		{
			name: "failed to query extended handle information",
			api: func(t *testing.T) *fakeWinAPI {
				fAPI := createDefaultFakeWinAPI(t)
				fAPI.queryHandleInformationErr = windows.STATUS_PROCESS_IS_TERMINATING

				return fAPI
			},
			expectErr: "failed to query for extended handle information:",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := &helper{
				wapi: tt.api(t),
			}

			logger := &fakeLogger{}

			containerID, err := h.GetContainerIDByProcess(123, logger)
			if tt.expectErr != "" {
				require.ErrorContains(t, err, tt.expectErr)
				require.Empty(t, tt.containerID)
				return
			}
			require.Empty(t, tt.expectErr)
			require.Equal(t, tt.containerID, containerID)
			require.Equal(t, tt.expectDebugLogs, logger.debugMsj)
		})
	}
}

func createDefaultFakeWinAPI(t *testing.T) *fakeWinAPI {
	return &fakeWinAPI{
		t: t,
		process32FirstEntry: &windows.ProcessEntry32{
			ProcessID: 1,
			ExeFile:   strToUTF16Max(t, "a.exe"),
		},
		process32NextEntries: []*windows.ProcessEntry32{
			{
				ProcessID: 2,
				ExeFile:   strToUTF16Max(t, "b.exe"),
			},
			{
				ProcessID: 3,
				ExeFile:   strToUTF16Max(t, "vmcompute.exe"),
			},
			{
				ProcessID: 4,
				ExeFile:   strToUTF16Max(t, "c.exe"),
			},
		},
		openProcessPIDs: []uint32{
			123,
			3,
		},
		queryHandleInformation: []SystemHandleInformationExItem{
			{
				UniqueProcessID: 3,
				HandleValue:     uintptr(456),
			},
			{
				UniqueProcessID: 3,
				HandleValue:     uintptr(789),
			},
			{
				UniqueProcessID: 1,
				HandleValue:     uintptr(windows.InvalidHandle),
			},
		},
		duplicateHandleResp: map[int32]int32{
			456: 4561,
			789: 7891,
		},
		getObjectTypeResp: map[int32]string{
			4561: "Handle",
			7891: "Job",
		},
		getObjectNameResp: map[int32]string{
			7891: `\Container_ABC123`,
		},
		isProcessInJobMap: map[int32]bool{
			7891: true,
		},
	}
}

func strToUTF16Max(t *testing.T, s string) [windows.MAX_PATH]uint16 {
	u, err := syscall.UTF16FromString(s)
	require.NoError(t, err)
	require.LessOrEqual(t, len(u), windows.MAX_PATH)

	var resp [windows.MAX_PATH]uint16
	_ = copy(resp[:], u)
	return resp
}

type fakeWinAPI struct {
	t *testing.T

	createSnapshotErr         error
	createSnapshotHandle      windows.Handle
	closeHandleErr            error
	process32FirstErr         error
	process32FirstEntry       *windows.ProcessEntry32
	process32NextEntries      []*windows.ProcessEntry32
	process32NextEntryErr     error
	openProcessPIDs           []uint32
	queryHandleInformation    []SystemHandleInformationExItem
	queryHandleInformationErr error
	isProcessInJobErr         error
	isProcessInJobMap         map[int32]bool
	getObjectTypeResp         map[int32]string
	getObjectNameResp         map[int32]string
	duplicateHandleErr        error
	duplicateHandleResp       map[int32]int32
}

func (f *fakeWinAPI) IsProcessInJob(procHandle windows.Handle, jobHandle windows.Handle, result *bool) error {
	// TODO: how can I solve what handle is correct
	*result = f.isProcessInJobMap[int32(jobHandle)]

	return f.isProcessInJobErr
}

func (f *fakeWinAPI) GetObjectType(handle windows.Handle) (string, error) {
	for h, r := range f.getObjectTypeResp {
		if h == int32(handle) {
			return r, nil
		}
	}

	return "", windows.ERROR_FILE_NOT_FOUND
}

func (f *fakeWinAPI) GetObjectName(handle windows.Handle) (string, error) {
	for h, r := range f.getObjectNameResp {
		if h == int32(handle) {
			return r, nil
		}
	}

	return "", windows.ERROR_FILE_NOT_FOUND
}

func (f *fakeWinAPI) QuerySystemExtendedHandleInformation() ([]SystemHandleInformationExItem, error) {
	if f.queryHandleInformationErr != nil {
		return nil, f.queryHandleInformationErr
	}

	return f.queryHandleInformation, nil
}

func (f *fakeWinAPI) CurrentProcess() windows.Handle {
	return windows.Handle(9999)
}

func (f *fakeWinAPI) CloseHandle(h windows.Handle) error {
	return f.closeHandleErr
}

func (f *fakeWinAPI) OpenProcess(desiredAccess uint32, inheritHandle bool, pID uint32) (windows.Handle, error) {
	for _, id := range f.openProcessPIDs {
		if id == pID {
			return windows.Handle(id), nil
		}
	}

	return windows.InvalidHandle, windows.ERROR_FILE_NOT_FOUND
}

func (f *fakeWinAPI) DuplicateHandle(hSourceProcessHandle windows.Handle, hSourceHandle windows.Handle, hTargetProcessHandle windows.Handle, lpTargetHandle *windows.Handle, dwDesiredAccess uint32, bInheritHandle bool, dwOptions uint32) error {
	if f.duplicateHandleErr != nil {
		return f.duplicateHandleErr
	}
	sourceHandle := int32(hSourceHandle)
	for hSource, hResp := range f.duplicateHandleResp {
		if hSource == sourceHandle {
			*lpTargetHandle = windows.Handle(hResp)

			return nil
		}
	}

	return windows.ERROR_FILE_NOT_FOUND
}

func (f *fakeWinAPI) CreateToolhelp32Snapshot(flags uint32, pID uint32) (windows.Handle, error) {
	if f.createSnapshotErr != nil {
		return windows.InvalidHandle, f.createSnapshotErr
	}

	assert.Equal(f.t, Th32csSnapProcess, flags)
	assert.Equal(f.t, uint32(0), pID)

	return f.createSnapshotHandle, nil
}

func (f *fakeWinAPI) Process32First(snapshot windows.Handle, procEntry *windows.ProcessEntry32) error {
	if f.process32FirstErr != nil {
		return f.process32FirstErr
	}

	*procEntry = *f.process32FirstEntry
	return nil
}

func (f *fakeWinAPI) Process32Next(snapshot windows.Handle, procEntry *windows.ProcessEntry32) error {
	if f.process32NextEntryErr != nil {
		return f.process32NextEntryErr
	}
	entry := f.getNextEntry()
	if entry == nil {
		return windows.ERROR_NO_MORE_FILES
	}
	*procEntry = *entry
	return nil
}

func (f *fakeWinAPI) getNextEntry() *windows.ProcessEntry32 {
	if len(f.process32NextEntries) == 0 {
		return nil
	}

	entry := f.process32NextEntries[0]
	f.process32NextEntries = f.process32NextEntries[1:]
	return entry
}

type fakeLogger struct {
	hclog.Logger

	debugMsj []string
}

func (l *fakeLogger) Debug(msg string, args ...interface{}) {
	l.debugMsj = append(l.debugMsj, fmt.Sprintf("%s: %v", msg, args))
}
