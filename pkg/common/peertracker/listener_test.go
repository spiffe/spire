package peertracker

import (
	"context"
	"errors"
	"net"
	"path"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/suite"
)

var errMockWatcherFailed = errors.New("create new watcher failed")

type failingMockTracker struct{}

func (failingMockTracker) Close() {}
func (failingMockTracker) NewWatcher(CallerInfo) (Watcher, error) {
	return nil, errMockWatcherFailed
}

func newFailingMockTracker() (PeerTracker, error) {
	return failingMockTracker{}, nil
}

func TestListenerTestSuite(t *testing.T) {
	suite.Run(t, new(ListenerTestSuite))
}

type ListenerTestSuite struct {
	suite.Suite

	ul       *Listener
	unixAddr *net.UnixAddr
}

func (p *ListenerTestSuite) SetupTest() {
	tempDir := spiretest.TempDir(p.T())
	p.unixAddr = &net.UnixAddr{
		Net:  "unix",
		Name: path.Join(tempDir, "test.sock"),
	}
}

func (p *ListenerTestSuite) TearDownTest() {
	// only close the listener if we haven't already
	if p.ul != nil {
		err := p.ul.Close()
		p.NoError(err)
		p.ul = nil
	}
}

func (p *ListenerTestSuite) TestAcceptDoesntFailWhenTrackerFails() {
	var err error
	logger, hook := test.NewNullLogger()
	logger.Level = logrus.WarnLevel
	lf := ListenerFactory{
		NewTracker: newFailingMockTracker,
		Log:        logger,
	}
	p.ul, err = lf.ListenUnix(p.unixAddr.Network(), p.unixAddr)
	p.Require().NoError(err)

	// used to cancel the log polling below if something goes wrong with
	// the test
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clientDone := make(chan error)
	peer := newFakeUDSPeer(p.T())

	peer.connect(p.unixAddr, clientDone)

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		conn, err := p.ul.Accept()
		acceptCh <- acceptResult{
			conn: conn,
			err:  err,
		}
	}()

	logCh := make(chan *logrus.Entry, 1)
	go func() {
		for {
			logEntry := hook.LastEntry()
			if logEntry == nil {
				select {
				case <-ctx.Done():
					close(logCh)
				case <-time.After(time.Millisecond * 10):
				}
				continue
			}
			logCh <- logEntry
		}
	}()

	// Wait for the logs to show up demonstrating the accept failure
	select {
	case logEntry := <-logCh:
		p.Require().NotNil(logEntry)
		p.Require().Equal("Connection failed during accept", logEntry.Message)
		logErr := logEntry.Data["error"]
		p.Require().IsType(errors.New(""), logErr)
		p.Require().EqualError(logErr.(error), "create new watcher failed")
	case <-time.After(time.Second):
		p.Require().Fail("waited too long for logs")
	}

	p.Require().NoError(p.ul.Close())
	p.ul = nil

	// Wait for the listener to stop
	select {
	case acceptRes := <-acceptCh:
		p.Require().Error(acceptRes.err)
		p.Require().Contains(acceptRes.err.Error(), "use of closed network connection")
		p.Require().Nil(acceptRes.conn)
	case <-time.After(time.Second):
		p.Require().Fail("waited too long for listener to close")
	}
}

func (p *ListenerTestSuite) TestAcceptFailsWhenUnderlyingAcceptFails() {
	lf := ListenerFactory{
		NewUnixListener: newFailingMockListenUnix,
		NewTracker:      newFailingMockTracker,
	}
	ul, err := lf.ListenUnix(p.unixAddr.Network(), p.unixAddr)
	p.Require().NoError(err)

	_, err = ul.Accept()
	p.Require().Error(err)
}

// returns an empty unix listener that will fail any call to Accept()
func newFailingMockListenUnix(network string, laddr *net.UnixAddr) (*net.UnixListener, error) {
	return &net.UnixListener{}, nil
}
