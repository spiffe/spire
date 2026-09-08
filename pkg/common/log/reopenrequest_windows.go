//go:build windows

package log

// reopenRequests carries reopen requests to ReopenOnSignal. POSIX has the
// kernel deliver SIGUSR2 straight to the log package, but on Windows the
// equivalent arrives as a service control code handled elsewhere in the
// process, so it needs somewhere to hand off. The buffer keeps RequestReopen
// from blocking, and a request arriving while one is already pending is
// dropped, since two reopens back to back would do the same work twice.
var reopenRequests = make(chan struct{}, 1)

// RequestReopen asks a running SPIRE to start writing to a new log file. It
// stands in for SIGUSR2, which Windows does not have, and is called when the
// service receives the reopen control code. It never blocks, because Windows
// expects a service control handler to return promptly.
func RequestReopen() {
	select {
	case reopenRequests <- struct{}{}:
	default:
	}
}
