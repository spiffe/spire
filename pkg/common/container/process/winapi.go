//go:build windows

package process

import (
	"reflect"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modntdll    = windows.NewLazySystemDLL("ntdll.dll")

	procIsProcessInJob    = modkernel32.NewProc("IsProcessInJob")
	procIsProcessInJobErr = procIsProcessInJob.Find()

	procNtQueryObject               = modntdll.NewProc("NtQueryObject")
	procNtQueryObjectErr            = procNtQueryObject.Find()
	procNtQuerySystemInformation    = modntdll.NewProc("NtQuerySystemInformation")
	procNtQuerySystemInformationErr = procNtQuerySystemInformation.Find()
)

const (
	// ObjectInformationClass values used to call NtQueryObject (https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject)
	ObjectNameInformationClass = 0x1
	ObjectTypeInformationClass = 0x2

	// Includes all processes in the system in the snapshot. (https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
	Th32csSnapProcess uint32 = 0x00000002
)

type API interface {
	// IsProcessInJob determines whether the process is running in the specified job.
	IsProcessInJob(procHandle windows.Handle, jobHandle windows.Handle, result *bool) error

	// GetObjectType gets the object type of the given handle
	GetObjectType(handle windows.Handle) (string, error)

	// GetObjectName gets the object name of the given handle
	GetObjectName(handle windows.Handle) (string, error)

	// QuerySystemExtendedHandleInformation retrieves Extended handle system information.
	QuerySystemExtendedHandleInformation() ([]SystemHandleInformationExItem, error)

	// CurrentProcess returns the handle for the current process.
	// It is a pseudo handle that does not need to be closed.
	CurrentProcess() windows.Handle

	// CloseHandle closes an open object handle.
	CloseHandle(h windows.Handle) error

	// OpenProcess returns an open handle
	OpenProcess(desiredAccess uint32, inheritHandle bool, pID uint32) (windows.Handle, error)

	// DuplicateHandle duplicates an object handle.
	DuplicateHandle(hSourceProcessHandle windows.Handle, hSourceHandle windows.Handle, hTargetProcessHandle windows.Handle, lpTargetHandle *windows.Handle, dwDesiredAccess uint32, bInheritHandle bool, dwOptions uint32) error

	// CreateToolhelp32Snapshot takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes.
	CreateToolhelp32Snapshot(flags uint32, pID uint32) (windows.Handle, error)

	// Process32First retrieves information about the first process encountered in a system snapshot.
	Process32First(snapshot windows.Handle, procEntry *windows.ProcessEntry32) error

	// Process32Next retrieves information about the next process recorded in a system snapshot.
	Process32Next(snapshot windows.Handle, procEntry *windows.ProcessEntry32) error
}

type api struct {
}

func (a *api) IsProcessInJob(procHandle windows.Handle, jobHandle windows.Handle, result *bool) error {
	if procIsProcessInJobErr != nil {
		return procIsProcessInJobErr
	}
	r1, _, e1 := syscall.SyscallN(procIsProcessInJob.Addr(), uintptr(procHandle), uintptr(jobHandle), uintptr(unsafe.Pointer(result)))
	if r1 == 0 {
		if e1 != 0 {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}

// GetObjectType gets the object type of the given handle
func (a *api) GetObjectType(handle windows.Handle) (string, error) {
	buffer := make([]byte, 1024*10)
	length := uint32(0)

	status := ntQueryObject(handle, ObjectTypeInformationClass,
		&buffer[0], uint32(len(buffer)), &length)
	if status != windows.STATUS_SUCCESS {
		return "", status
	}

	return (*ObjectTypeInformation)(unsafe.Pointer(&buffer[0])).TypeName.String(), nil
}

// GetObjectName gets the object name of the given handle
func (a *api) GetObjectName(handle windows.Handle) (string, error) {
	buffer := make([]byte, 1024*2)
	var length uint32

	status := ntQueryObject(handle, ObjectNameInformationClass,
		&buffer[0], uint32(len(buffer)), &length)
	if status != windows.STATUS_SUCCESS {
		return "", status
	}

	return (*UnicodeString)(unsafe.Pointer(&buffer[0])).String(), nil
}

func (a *api) QuerySystemExtendedHandleInformation() ([]SystemHandleInformationExItem, error) {
	buffer := make([]byte, 1024)
	var retLen uint32
	var status windows.NTStatus

	for {
		status = ntQuerySystemInformation(
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
		}
		// if no error
		break
	}

	if status>>30 != 3 {
		buffer = (buffer)[:int(retLen)]

		handlesList := (*SystemExtendedHandleInformation)(unsafe.Pointer(&buffer[0]))
		handles := make([]SystemHandleInformationExItem, int(handlesList.NumberOfHandles))
		hdr := (*reflect.SliceHeader)(unsafe.Pointer(&handles))
		hdr.Data = uintptr(unsafe.Pointer(&handlesList.Handles[0]))

		return handles, nil
	}

	return nil, status
}

func (a *api) OpenProcess(desiredAccess uint32, inheritHandle bool, pID uint32) (windows.Handle, error) {
	return windows.OpenProcess(desiredAccess, inheritHandle, pID)
}

func (a *api) CloseHandle(h windows.Handle) error {
	return windows.CloseHandle(h)
}

// CurrentProcess returns the handle for the current process.
// It is a pseudo handle that does not need to be closed.
func (a *api) CurrentProcess() windows.Handle {
	return windows.CurrentProcess()
}

func (a *api) DuplicateHandle(hSourceProcessHandle windows.Handle, hSourceHandle windows.Handle, hTargetProcessHandle windows.Handle, lpTargetHandle *windows.Handle, dwDesiredAccess uint32, bInheritHandle bool, dwOptions uint32) error {
	return windows.DuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions)
}

func (a *api) CreateToolhelp32Snapshot(flags uint32, pID uint32) (windows.Handle, error) {
	return windows.CreateToolhelp32Snapshot(flags, pID)
}

func (a *api) Process32First(snapshot windows.Handle, procEntry *windows.ProcessEntry32) error {
	return windows.Process32First(snapshot, procEntry)
}

func (a *api) Process32Next(snapshot windows.Handle, procEntry *windows.ProcessEntry32) error {
	return windows.Process32Next(snapshot, procEntry)
}

// System handle extended information item, returned by NtQuerySystemInformation (https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation)
type SystemHandleInformationExItem struct {
	Object                uintptr
	UniqueProcessID       uintptr
	HandleValue           uintptr
	GrantedAccess         uint32
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint16
	HandleAttributes      uint32
	Reserved              uint32
}

// System extended handle information summary, returned by NtQuerySystemInformation (https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation)
type SystemExtendedHandleInformation struct {
	NumberOfHandles uintptr
	Reserved        uintptr
	Handles         [1]SystemHandleInformationExItem
}

// Object type returned by calling NtQueryObject function
type ObjectTypeInformation struct {
	TypeName               UnicodeString
	TotalNumberOfObjects   uint32
	TotalNumberOfHandles   uint32
	TotalPagedPoolUsage    uint32
	TotalNonPagedPoolUsage uint32
}

// Unicode string returned by NtQueryObject calls (https://docs.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string)
type UnicodeString struct {
	Length        uint16
	AllocatedSize uint16
	WString       *byte
}

func (u UnicodeString) String() string {
	defer func() {
		// TODO: may we recover?
		_ = recover()
	}()

	var data []uint16

	sh := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	sh.Data = uintptr(unsafe.Pointer(u.WString))
	sh.Len = int(u.Length * 2)
	sh.Cap = int(u.Length * 2)

	return windows.UTF16ToString(data)
}

func ntQueryObject(handle windows.Handle, objectInformationClass uint32, objectInformation *byte, objectInformationLength uint32, returnLength *uint32) (ntStatus windows.NTStatus) {
	if procNtQueryObjectErr != nil {
		return windows.STATUS_PROCEDURE_NOT_FOUND
	}
	r0, _, _ := syscall.SyscallN(procNtQueryObject.Addr(), uintptr(handle), uintptr(objectInformationClass), uintptr(unsafe.Pointer(objectInformation)), uintptr(objectInformationLength), uintptr(unsafe.Pointer(returnLength)), 0)
	if r0 != 0 {
		ntStatus = windows.NTStatus(r0)
	}
	return
}

func ntQuerySystemInformation(sysInfoClass int32, sysInfo unsafe.Pointer, sysInfoLen uint32, retLen *uint32) (ntstatus windows.NTStatus) {
	if procNtQuerySystemInformationErr != nil {
		return windows.STATUS_PROCEDURE_NOT_FOUND
	}
	r0, _, _ := syscall.SyscallN(procNtQuerySystemInformation.Addr(), uintptr(sysInfoClass), uintptr(sysInfo), uintptr(sysInfoLen), uintptr(unsafe.Pointer(retLen)), 0, 0)
	if r0 != 0 {
		ntstatus = windows.NTStatus(r0)
	}

	return
}
