//go:build windows
// +build windows

package peertracker

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (

	// iphlpapi.dll module contains functions used by the IP Helper API
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	// GetExtendedTcpTable function (iphlpapi.h)
	procGetExtendedTCPTable = modiphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	// Any size array
	ANY_SIZE = 1

	// The TCP connection is in the ESTABLISHED state.
	// https://docs.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow2
	MIB_TCP_STATE_ESTAB = 5
)

type TCP_CONNECTION_OFFLOAD_STATE int32

// MIB_TCPROW_OWNER_PID structure (tcpmib.h)
// The MIB_TCPROW_OWNER_PID structure contains information that
// describes an IPv4 TCP connection with IPv4 addresses, ports
// used by the TCP connection, and the specific process ID (PID)
// associated with the connection.
// https://docs.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_pid
type MIB_TCPROW_OWNER_PID struct {
	state      uint32
	localAddr  uint32
	localPort  uint32
	remoteAddr uint32
	remotePort uint32
	owningPID  uint32
}

// MIB_TCPTABLE_OWNER_PID structure (tcpmib.h)
// The MIB_TCPTABLE_OWNER_PID structure contains a table of process IDs (PIDs)
// and the IPv4 TCP links that are context bound to these PIDs.
// https://docs.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcptable_owner_pid
type MIB_TCPTABLE_OWNER_PID struct {
	numEntries uint32
	table      [ANY_SIZE]MIB_TCPROW_OWNER_PID
}

type TCP_TABLE_CLASS int32

// TCP_TABLE_CLASS enumeration (iprtrmib.h)
// The TCP_TABLE_CLASS enumeration defines the set of values used to indicate
// the type of table returned by calls to GetExtendedTcpTable.
// https://docs.microsoft.com/en-us/windows/win32/api/iprtrmib/ne-iprtrmib-tcp_table_class
const (
	TCP_TABLE_BASIC_LISTENER TCP_TABLE_CLASS = iota
	TCP_TABLE_BASIC_CONNECTIONS
	TCP_TABLE_BASIC_ALL
	TCP_TABLE_OWNER_PID_LISTENER
	TCP_TABLE_OWNER_PID_CONNECTIONS
	TCP_TABLE_OWNER_PID_ALL
	TCP_TABLE_OWNER_MODULE_LISTENER
	TCP_TABLE_OWNER_MODULE_CONNECTIONS
	TCP_TABLE_OWNER_MODULE_ALL
)

func getUintptrFromBool(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}

// GetExtendedTcpTable retrieves a table that contains a list
// of TCP endpoints available to the application.
func GetExtendedTcpTable(tcpTable uintptr,
	size *uint32,
	order bool,
	af uint32,
	tableClass TCP_TABLE_CLASS,
	reserved uint32) (errcode error) {
	r1, _, _ := syscall.Syscall6(procGetExtendedTCPTable.Addr(),
		6, // Number of arguments
		tcpTable,
		uintptr(unsafe.Pointer(size)),
		getUintptrFromBool(order),
		uintptr(af),
		uintptr(tableClass),
		uintptr(reserved))

	if r1 != 0 {
		return syscall.Errno(r1)
	}

	return nil
}
