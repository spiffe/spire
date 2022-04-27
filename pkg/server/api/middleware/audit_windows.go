//go:build windows
// +build windows

package middleware

import (
	"fmt"
	"syscall"

	"github.com/shirou/gopsutil/v3/process"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"golang.org/x/sys/windows"
)

// setFields sets audit log fields specific to the Windows platform.
func setFields(p *process.Process, fields logrus.Fields) error {
	userSID, err := getUserSID(p.Pid)
	if err != nil {
		return err
	}
	fields[telemetry.CallerUserSID] = userSID

	// We don't set group information on Windows. Setting the primary group
	// would be confusing, since it is used only by the POSIX subsystem.
	return nil
}

func getUserSID(pID int32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pID))
	if err != nil {
		return "", fmt.Errorf("failed to open process: %w", err)
	}
	defer func() {
		_ = windows.CloseHandle(h)
	}()

	// Retrieve an access token to describe the security context of
	// the process from which we obtained the handle.
	var token windows.Token
	err = windows.OpenProcessToken(h, syscall.TOKEN_QUERY, &token)
	if err != nil {
		return "", fmt.Errorf("failed to open the access token associated with the process: %w", err)
	}
	defer func() {
		_ = token.Close()
	}()
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve user account information from access token: %w", err)
	}
	return tokenUser.User.Sid.String(), nil
}
