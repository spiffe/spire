package peertracker

import (
	"net"
)

var _ net.Listener = &Listener{}

type Listener struct {
	l       net.Listener
	Tracker PeerTracker
}

func ListenUnix(network string, laddr *net.UnixAddr) (*Listener, error) {
	l, err := net.ListenUnix(network, laddr)
	if err != nil {
		return nil, err
	}

	tracker, err := NewTracker()
	if err != nil {
		l.Close()
		return nil, err
	}

	return &Listener{
		l:       l,
		Tracker: tracker,
	}, nil
}

func (l *Listener) Accept() (net.Conn, error) {
	var caller CallerInfo
	var err error

	conn, err := l.l.Accept()
	if err != nil {
		return conn, err
	}

	// Support future Listener types
	switch conn.RemoteAddr().Network() {
	case "unix":
		caller, err = CallerFromUDSConn(conn)
	default:
		err = ErrUnsupportedTransport
	}

	if err != nil {
		conn.Close()
		return nil, err
	}

	watcher, err := l.Tracker.NewWatcher(caller)
	if err != nil {
		// TODO: Error here could indicate PID race. Should we
		// allow the connection to stay open and instead fail
		// later on during attestation?
		conn.Close()
		return nil, err
	}

	wrappedConn := &Conn{
		Conn: conn,
		Info: AuthInfo{
			Caller:  caller,
			Watcher: watcher,
		},
	}

	return wrappedConn, nil
}

func (l *Listener) Close() error {
	l.Tracker.Close()
	return l.l.Close()
}

func (l *Listener) Addr() net.Addr {
	return l.l.Addr()
}
