//go:build !windows

package log

// ReopenOnSignalSupported reports whether a rotation can be triggered from
// outside the process on this platform.
const ReopenOnSignalSupported = true
