package peertracker

import (
	"io"
	"net"

	"github.com/sirupsen/logrus"
)

var _ net.Listener = &Listener{}

type ListenerFactory struct {
	Log               logrus.FieldLogger
	NewTracker        func(log logrus.FieldLogger) (PeerTracker, error)
	ListenerFactoryOS // OS specific
}

type Listener struct {
	l       net.Listener
	log     logrus.FieldLogger
	Tracker PeerTracker
}

func newNoopLogger() *logrus.Logger {
	logger := logrus.New()
	logger.Out = io.Discard
	return logger
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
		case "pipe":
			caller, err = CallerFromNamedPipeConn(conn)
		default:
			err = ErrUnsupportedTransport
		}

		if err != nil {
			l.log.WithError(err).Warn("Connection failed during accept")
			conn.Close()
			continue
		}

		watcher, err := l.Tracker.NewWatcher(caller)
		if err != nil {
			l.log.WithError(err).Warn("Connection failed during accept")
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
