//go:build windows
// +build windows

package peertracker

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func getCallerInfoFromTCPConn(conn net.Conn) (CallerInfo, error) {
	agentAddr, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return CallerInfo{}, ErrInvalidConnection
	}

	callerAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return CallerInfo{}, ErrInvalidConnection
	}

	pid, err := getOwningPIDFromLocalConn(callerAddr.Port, agentAddr.Port)
	if err != nil {
		return CallerInfo{}, fmt.Errorf("failed to get owning PID: %v", err)
	}

	uid, gid, err := getSIDsFromPID(pid)
	if err != nil {
		return CallerInfo{}, fmt.Errorf("failed to get process token: %v", err)
	}

	return CallerInfo{
		Addr: conn.RemoteAddr(),
		PID:  int32(pid),
		UID:  uid,
		GID:  gid,
	}, nil
}

func ip(ipUint uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipUint)
	return ip
}

func port(port uint32) uint16 {
	return syscall.Ntohs(uint16(port))
}

// getSIDsFromPID gets the security identifiers (SIDs) based on the
// access token associated with the provided process ID (pid).
// The security identifiers returned are the SID of the user account
// that is running the process identified by the pid and the SID
// representing a group that will become the primary group of any
// objects created by a process using the obtained access token.
func getSIDsFromPID(pid int) (uid, gid string, err error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", "", err
	}
	defer windows.CloseHandle(h)

	var token syscall.Token
	err = syscall.OpenProcessToken(syscall.Handle(h), syscall.TOKEN_QUERY, &token)
	if err != nil {
		return "", "", err
	}
	defer token.Close()
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", "", err
	}
	uid, err = tokenUser.User.Sid.String()
	if err != nil {
		return "", "", err
	}
	tokenGroup, err := token.GetTokenPrimaryGroup()
	if err != nil {
		return "", "", err
	}
	gid, err = tokenGroup.PrimaryGroup.String()
	if err != nil {
		return "", "", err
	}

	return uid, gid, nil
}

func getOwningPIDFromLocalConn(localPort, remotePort int) (pid int, err error) {
	var (
		localHost = net.IPv4(127, 0, 0, 1)

		tcpTable *MIB_TCPTABLE_OWNER_PID
		buffer   []byte
		size     uint32
	)

	for {
		if len(buffer) > 0 {
			tcpTable = (*MIB_TCPTABLE_OWNER_PID)(unsafe.Pointer(&buffer[0]))
		}
		err := GetExtendedTcpTable(uintptr(unsafe.Pointer(tcpTable)),
			&size,
			true,
			syscall.AF_INET,
			TCP_TABLE_OWNER_PID_ALL,
			0)
		if err == nil {
			break
		}

		if err != windows.ERROR_INSUFFICIENT_BUFFER {
			return 0, err
		}
		// The call to GetExtendedTcpTable returned ERROR_INSUFFICIENT_BUFFER
		// We have now an updated value of the size parameter.
		// Allocate a byte buffer with that size.
		buffer = make([]byte, size)
	}

	if int(tcpTable.numEntries) == 0 {
		return 0, errors.New("no entries in TCP table")
	}

	index := int(unsafe.Sizeof(tcpTable.numEntries))
	tcpTableSize := int(unsafe.Sizeof(tcpTable.table))

	for i := 0; i < int(tcpTable.numEntries); i++ {
		tcpEntry := (*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&buffer[index]))

		if localHost.Equal(ip(tcpEntry.localAddr)) &&
			port(tcpEntry.localPort) == uint16(localPort) &&
			localHost.Equal(ip(tcpEntry.remoteAddr)) &&
			port(tcpEntry.remotePort) == uint16(remotePort) &&
			tcpEntry.state == MIB_TCP_STATE_ESTAB {
			return int(tcpEntry.owningPID), nil
		}

		index += tcpTableSize
	}

	return 0, errors.New("no matching entry in TCP table")
}
