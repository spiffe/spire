//go:build windows
// +build windows

package peertracker

import (
	"net"
)

type CallerInfo struct {
	Addr net.Addr
	PID  int32
	UID  string
	GID  string
}
