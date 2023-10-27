//go:build !windows

package peertracker

import "net"

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

	tracker, err := lf.NewTracker(lf.Log)
	if err != nil {
		l.Close()
		return nil, err
	}

	return &Listener{
		l:       l,
		Tracker: tracker,
		log:     lf.Log,
	}, nil
}
