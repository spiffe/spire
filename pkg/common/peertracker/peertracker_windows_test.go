//go:build windows

package peertracker

import (
	"testing"
)

func requireCallerExitFailedDirent(_ testing.TB, _ any) {
	// No-op on Windows, only relevant for Unix systems
}
