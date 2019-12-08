package peertracker

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

func TestPeerTrackerTestSuite(t *testing.T) {
	suite.Run(t, new(PeerTrackerTestSuite))
}

type PeerTrackerTestSuite struct {
	suite.Suite

	childPath string
	tempDir   string
	ul        *Listener
	unixAddr  *net.UnixAddr
}

func (p *PeerTrackerTestSuite) SetupTest() {
	var err error

	p.tempDir, err = ioutil.TempDir("", "spire-peertracker-test")
	p.NoError(err)

	p.childPath = path.Join(p.tempDir, "child")
	buildOutput, err := exec.Command("go", "build", "-o", p.childPath, "peertracker_test_child.go").CombinedOutput()
	if err != nil {
		p.T().Logf("build output:\n%v\n", string(buildOutput))
		p.FailNow("failed to build test child")
	}

	p.unixAddr = &net.UnixAddr{
		Net:  "unix",
		Name: path.Join(p.tempDir, "test.sock"),
	}

	p.ul, err = (&ListenerFactory{}).ListenUnix(p.unixAddr.Network(), p.unixAddr)
	p.NoError(err)
}

func (p *PeerTrackerTestSuite) TearDownTest() {
	// only close the listener if we haven't already
	if p.ul != nil {
		err := p.ul.Close()
		p.NoError(err)
	}

	err := os.Remove(p.childPath)
	p.NoError(err)

	err = os.Remove(p.tempDir)
	p.NoError(err)
}

func (p *PeerTrackerTestSuite) TestTrackerClose() {
	p.ul.Tracker.Close()
	_, err := p.ul.Tracker.NewWatcher(CallerInfo{})
	p.Error(err)
}

func (p *PeerTrackerTestSuite) TestUDSListener() {
	peer := newFakeUDSPeer(p.T())

	sErrCh := make(chan error, 1)
	connCh := make(chan net.Conn)
	go func() {
		defer close(connCh)
		rawConn, err := p.ul.Accept()
		if err != nil {
			sErrCh <- err
			return
		}
		connCh <- rawConn
	}()

	cErrCh := make(chan error, 1)
	peer.connect(p.unixAddr, cErrCh)

	// Ensure server had no errors
	select {
	case err := <-sErrCh:
		p.Require().NoError(err)
	case <-time.After(time.Duration(time.Second)):
		p.Error(errors.New("connection timed out"))
	}

	// Ensure client had no errors
	select {
	case err := <-cErrCh:
		p.Require().NoError(err)
	case <-time.After(time.Duration(time.Second)):
		p.Error(errors.New("connection timed out"))
	}

	// get result from server
	rawConn := <-connCh
	conn, ok := rawConn.(*Conn)
	p.Require().True(ok)

	// Ensure we resolved the PID ok
	p.Equal(int32(os.Getpid()), conn.Info.Caller.PID)

	// Ensure watcher is set up correctly
	p.NotNil(conn.Info.Watcher)
	p.Equal(int32(os.Getpid()), conn.Info.Watcher.PID())

	conn.Close()
}

func (p *PeerTrackerTestSuite) TestExitDetection() {
	peer := newFakeUDSPeer(p.T())

	sErrCh := make(chan error, 1)
	connCh := make(chan net.Conn)
	go func() {
		defer close(connCh)
		rawConn, err := p.ul.Accept()
		if err != nil {
			sErrCh <- err
			return
		}
		connCh <- rawConn
	}()

	cErrCh := make(chan error, 1)
	peer.connect(p.unixAddr, cErrCh)

	// Ensure server had no errors
	select {
	case err := <-sErrCh:
		p.Require().NoError(err)
	case <-time.After(time.Duration(time.Second)):
		p.Error(errors.New("connection timed out"))
	}

	// Ensure client had no errors
	select {
	case err := <-cErrCh:
		p.Require().NoError(err)
	case <-time.After(time.Duration(time.Second)):
		p.Error(errors.New("connection timed out"))
	}

	// get result from server
	rawConn := <-connCh
	conn, ok := rawConn.(*Conn)
	p.Require().True(ok)

	// We're connected to ourselves - we should be alive!
	p.NoError(conn.Info.Watcher.IsAlive())

	// Should return an error once we're no longer tracking
	conn.Close()
	p.EqualError(conn.Info.Watcher.IsAlive(), "caller is no longer being watched")

	// Start a forking child and allow it to exit while the grandchild holds the socket
	doneCh := make(chan struct{})
	peer.connectFromForkingChild(p.unixAddr, p.childPath, doneCh)

	rawConn, err := p.ul.Accept()

	// Unblock child connect goroutine
	<-doneCh

	// Check for Accept() error only after unblocking
	// the child so we can be sure that we that we can
	// clean up correctly
	defer peer.killGrandchild()
	p.Require().NoError(err)

	conn, ok = rawConn.(*Conn)
	p.Require().True(ok)

	// We know the child has exited because we read from doneCh
	// Call to IsAlive should now return an error
	switch runtime.GOOS {
	case "darwin":
		p.EqualError(conn.Info.Watcher.IsAlive(), "caller exit detected via kevent notification")
	case "linux":
		p.EqualError(conn.Info.Watcher.IsAlive(), "caller exit suspected due to failed readdirent: err=no such file or directory")
	default:
		p.FailNow("missing case for OS specific failure")
	}

	// Read a bit of data from our grandchild just to be sure it's still there
	theSign := make([]byte, 10)
	expectedSign := []byte("i'm alive!")
	_, err = conn.Read(theSign)
	p.Require().NoError(err)
	p.Equal(expectedSign, theSign)

	conn.Close()

	// Check that IsAlive doesn't freak out if called after
	// the tracker has been closed
	p.ul.Close()
	p.ul = nil
	p.EqualError(conn.Info.Watcher.IsAlive(), "caller is no longer being watched")
}

type fakeUDSPeer struct {
	grandchildPID int
	conn          net.Conn
	t             *testing.T
}

func newFakeUDSPeer(t *testing.T) *fakeUDSPeer {
	return &fakeUDSPeer{
		t: t,
	}
}

// connect to the uds listener
func (f *fakeUDSPeer) connect(addr *net.UnixAddr, errCh chan error) {
	defer close(errCh)
	if f.conn != nil {
		errCh <- errors.New("fake peer already connected")
		return
	}

	go func() {
		conn, err := net.DialUnix("unix", nil, addr)
		if err != nil {
			errCh <- fmt.Errorf("could not dial unix address: %v", err)
			return
		}

		f.conn = conn
	}()
}

// run child to connect and fork. allows us to test stale PID data
func (f *fakeUDSPeer) connectFromForkingChild(addr *net.UnixAddr, childPath string, doneCh chan struct{}) {
	if f.grandchildPID != 0 {
		f.t.Fatalf("grandchild already running with PID %v", f.grandchildPID)
	}

	go func() {
		out, err := exec.Command(childPath, "-socketPath", addr.Name).Output()
		if err != nil {
			f.t.Fatalf("child process failed: %v", err)
		}

		// Get and store the grandchild PID from our child's STDOUT
		grandchildPID, err := strconv.ParseInt(string(out), 10, 0)
		if err != nil {
			f.t.Fatalf("could not get grandchild pid: %v", err)
		}

		f.grandchildPID = int(grandchildPID)
		doneCh <- struct{}{}
	}()
}

// muahaha
func (f *fakeUDSPeer) killGrandchild() {
	if f.grandchildPID == 0 {
		f.t.Fatal("no known grandchild")
	}

	err := syscall.Kill(f.grandchildPID, syscall.SIGKILL)
	if err != nil {
		f.t.Fatalf("unable to kill grandchild: %v", err)
	}

	f.grandchildPID = 0
}
