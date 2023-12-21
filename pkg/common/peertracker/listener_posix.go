//go:build !windows

package peertracker

import (
	"net"
	"syscall"

	"golang.org/x/net/netutil"
)

type ListenerFactoryOS struct {
	NewUnixListener func(network string, laddr *net.UnixAddr) (*net.UnixListener, error)
}

func (lf *ListenerFactory) ListenUnix(network string, laddr *net.UnixAddr) (*Listener, error) {
	if lf.NewUnixListener == nil {
		lf.NewUnixListener = net.ListenUnix
	}
	if lf.NewTracker == nil {
		lf.NewTracker = NewTracker
	}
	if lf.Log == nil {
		lf.Log = newNoopLogger()
	}
	return lf.listenUnix(network, laddr)
}

func (lf *ListenerFactory) listenUnix(network string, laddr *net.UnixAddr) (*Listener, error) {
	l, err := lf.NewUnixListener(network, laddr)
	if err != nil {
		return nil, err
	}
	limitedListener, err := lf.limitListenerBelowRlimit(l)
	if err != nil {
		return nil, err
	}

	tracker, err := lf.NewTracker(lf.Log)
	if err != nil {
		l.Close()
		return nil, err
	}

	return &Listener{
		l:       limitedListener,
		Tracker: tracker,
		log:     lf.Log,
	}, nil
}

func (lf *ListenerFactory) limitListenerBelowRlimit(l net.Listener) (net.Listener, error) {
	var (
		concurrency   int
		rlimit        syscall.Rlimit
		rlimitPercent uint64 = 99
	)
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
		return l, err
	}
	concurrency = int(rlimit.Cur * rlimitPercent / 100)
	// FIXME: placeholder log message needs wordsmithing
	lf.Log.Infof("rlimit: %d concurrency: %d", rlimit.Cur, int(concurrency))

	return netutil.LimitListener(l, int(concurrency)), nil
}
