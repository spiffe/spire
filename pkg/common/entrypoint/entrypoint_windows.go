//go:build windows
// +build windows

package entrypoint

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"golang.org/x/sys/windows/svc"
)

type systemCaller interface {
	IsWindowsService() (bool, error)
	Run(name string, handler svc.Handler) error
}

type systemCall struct {
}

func (s *systemCall) IsWindowsService() (bool, error) {
	// We are using a custom function because the svc.IsWindowsService() one still has an open issue in which it states
	// that it is not working properly in Windows containers: https://github.com/golang/go/issues/56335. Soon as we have
	// a fix for that, we can use the original function.
	return isWindowsService()
}

func (s *systemCall) Run(name string, handler svc.Handler) error {
	return svc.Run(name, handler)
}

type EntryPoint struct {
	handler  svc.Handler
	runCmdFn func(ctx context.Context, args []string) int
	sc       systemCaller
}

func NewEntryPoint(runCmdFn func(ctx context.Context, args []string) int) *EntryPoint {
	return &EntryPoint{
		runCmdFn: runCmdFn,
		handler: &service{
			executeServiceFn: func(ctx context.Context, stop context.CancelFunc, args []string) int {
				defer stop()
				retCode := runCmdFn(ctx, args[1:])
				return retCode
			},
		},
		sc: &systemCall{},
	}
}

func (e *EntryPoint) Main() int {
	// Determining if SPIRE is running as a Windows service is done
	// with a best-effort approach. If there is an error, just fallback
	// to the behavior of not running as a Windows service.
	isWindowsSvc, err := e.sc.IsWindowsService()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not determine if running as a Windows service: %v", err)
	}
	if isWindowsSvc {
		errChan := make(chan error)
		go func() {
			// Since the service runs in its own process, the service name is ignored.
			// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicectrldispatcherw
			errChan <- e.sc.Run("", e.handler)
		}()
		err = <-errChan
		if err != nil {
			return 1
		}
		return 0
	}

	return e.runCmdFn(context.Background(), os.Args[1:])
}

// isWindowsService is a copy of the svc.IsWindowsService() function, but without the parentProcess.SessionID == 0 check
// that is causing the issue in Windows containers, this logic is exactly the same from .NET runtime (>= 6.0.10).
func isWindowsService() (bool, error) {
	// The below technique looks a bit hairy, but it's actually
	// exactly what the .NET runtime (>= 6.0.10) does for the similarly named function:
	// https://github.com/dotnet/runtime/blob/36bf84fc4a89209f4fdbc1fc201e81afd8be49b0/src/libraries/Microsoft.Extensions.Hosting.WindowsServices/src/WindowsServiceHelpers.cs#L20-L33
	// Specifically, it looks up whether the parent process is called "services".

	var currentProcess windows.PROCESS_BASIC_INFORMATION
	infoSize := uint32(unsafe.Sizeof(currentProcess))
	err := windows.NtQueryInformationProcess(windows.CurrentProcess(), windows.ProcessBasicInformation, unsafe.Pointer(&currentProcess), infoSize, &infoSize)
	if err != nil {
		return false, err
	}
	var parentProcess *windows.SYSTEM_PROCESS_INFORMATION
	for infoSize = uint32((unsafe.Sizeof(*parentProcess) + unsafe.Sizeof(uintptr(0))) * 1024); ; {
		parentProcess = (*windows.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&make([]byte, infoSize)[0]))
		err = windows.NtQuerySystemInformation(windows.SystemProcessInformation, unsafe.Pointer(parentProcess), infoSize, &infoSize)
		if err == nil {
			break
		} else if !errors.Is(err, windows.STATUS_INFO_LENGTH_MISMATCH) {
			return false, err
		}
	}
	for ; ; parentProcess = (*windows.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(uintptr(unsafe.Pointer(parentProcess)) + uintptr(parentProcess.NextEntryOffset))) {
		if parentProcess.UniqueProcessID == currentProcess.InheritedFromUniqueProcessId {
			return strings.EqualFold("services.exe", parentProcess.ImageName.String()), nil
		}
		if parentProcess.NextEntryOffset == 0 {
			break
		}
	}
	return false, nil
}
