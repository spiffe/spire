package peertracker

import (
	"io/ioutil"
	"net"

	"github.com/sirupsen/logrus"
)

var _ net.Listener = &Listener{}

type ListenerFactory struct {
	Log             logrus.FieldLogger
	NewTracker      func() (PeerTracker, error)
	NewUnixListener func(network string, laddr *net.UnixAddr) (*net.UnixListener, error)
}

type Listener struct {
	l       net.Listener
	log     logrus.FieldLogger
	Tracker PeerTracker
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

func newNoopLogger() *logrus.Logger {
	logger := logrus.New()
	logger.Out = ioutil.Discard
	return logger
}

func (lf *ListenerFactory) listenUnix(network string, laddr *net.UnixAddr) (*Listener, error) {
	l, err := lf.NewUnixListener(network, laddr)
	if err != nil {
		return nil, err
	}

	tracker, err := lf.NewTracker()
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

func (l *Listener) Accept() (net.Conn, error) {
	for {
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
			l.log.WithError(err).Warn("Connection failed during accept.")
			conn.Close()
			continue
		}

		watcher, err := l.Tracker.NewWatcher(caller)
		if err != nil {
			l.log.WithError(err).Warn("Connection failed during accept.")
			conn.Close()
			continue
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
}

func (l *Listener) Close() error {
	l.Tracker.Close()
	return l.l.Close()
}

func (l *Listener) Addr() net.Addr {
	return l.l.Addr()
}
