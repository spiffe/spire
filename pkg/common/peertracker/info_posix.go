//go:build !windows
// +build !windows

package peertracker

import (
	"net"
)

type CallerInfo struct {
	Addr net.Addr
	PID  int32
	UID  uint32
	GID  uint32
}
