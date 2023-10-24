//go:build windows

package peertracker

func requireCallerExitFailedDirent(tb testing.TB, actual any) {
	// No-op on Windows, only relevant for Unix systems
}
