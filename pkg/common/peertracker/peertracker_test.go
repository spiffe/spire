package peertracker

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strconv"
	"syscall"
	"testing"

	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/suite"
)

func TestPeerTrackerTestSuite(t *testing.T) {
	suite.Run(t, new(PeerTrackerTestSuite))
}

type PeerTrackerTestSuite struct {
	suite.Suite

	childPath string
	ul        *Listener
	unixAddr  *net.UnixAddr
	logHook   *logtest.Hook
}

func (p *PeerTrackerTestSuite) SetupTest() {
	tempDir := spiretest.TempDir(p.T())

	p.childPath = path.Join(tempDir, "child")
	buildOutput, err := exec.Command("go", "build", "-o", p.childPath, "peertracker_test_child.go").CombinedOutput() //nolint: gosec // false positive
	if err != nil {
		p.T().Logf("build output:\n%v\n", string(buildOutput))
		p.FailNow("failed to build test child")
	}

	p.unixAddr = &net.UnixAddr{
		Net:  "unix",
		Name: path.Join(tempDir, "test.sock"),
	}

	log, hook := logtest.NewNullLogger()
	p.logHook = hook

	p.ul, err = (&ListenerFactory{Log: log}).ListenUnix(p.unixAddr.Network(), p.unixAddr)
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
}

func (p *PeerTrackerTestSuite) TestTrackerClose() {
	p.ul.Tracker.Close()
	_, err := p.ul.Tracker.NewWatcher(CallerInfo{})
	p.Error(err)
}

func (p *PeerTrackerTestSuite) TestUDSListener() {
	doneCh := make(chan error)
	peer := newFakeUDSPeer(p.T())

	peer.connect(p.unixAddr, doneCh)

	rawConn, err := p.ul.Accept()
	p.Require().NoError(err)

	// Unblock connect goroutine
	p.Require().NoError(<-doneCh)

	conn, ok := rawConn.(*Conn)
	p.Require().True(ok)

	// Ensure we resolved the PID ok
	p.Equal(int32(os.Getpid()), conn.Info.Caller.PID)

	// Ensure watcher is set up correctly
	p.NotNil(conn.Info.Watcher)
	p.Equal(int32(os.Getpid()), conn.Info.Watcher.PID())

	peer.disconnect()
	conn.Close()
}

func (p *PeerTrackerTestSuite) TestExitDetection() {
	// First, just test against ourselves
	doneCh := make(chan error)
	peer := newFakeUDSPeer(p.T())

	peer.connect(p.unixAddr, doneCh)

	rawConn, err := p.ul.Accept()
	p.Require().NoError(err)

	// Unblock connect goroutine
	p.Require().NoError(<-doneCh)

	conn, ok := rawConn.(*Conn)
	p.Require().True(ok)

	// We're connected to ourselves - we should be alive!
	p.NoError(conn.Info.Watcher.IsAlive())

	// Should return an error once we're no longer tracking
	peer.disconnect()
	conn.Close()
	p.EqualError(conn.Info.Watcher.IsAlive(), "caller is no longer being watched")

	// Start a forking child and allow it to exit while the grandchild holds the socket
	peer.connectFromForkingChild(p.unixAddr, p.childPath, doneCh)

	rawConn, err = p.ul.Accept()

	// Unblock child connect goroutine
	p.Require().NoError(<-doneCh)

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
		p.Require().Len(p.logHook.Entries, 2)
		firstEntry := p.logHook.Entries[0]
		p.Require().Equal(logrus.WarnLevel, firstEntry.Level)
		p.Require().Equal("Caller is no longer being watched", firstEntry.Message)
		secondEntry := p.logHook.Entries[1]
		p.Require().Equal(logrus.WarnLevel, secondEntry.Level)
		p.Require().Equal("Caller exit detected via kevent notification", secondEntry.Message)
	case "linux":
		p.EqualError(conn.Info.Watcher.IsAlive(), "caller exit suspected due to failed readdirent")
		p.Require().Len(p.logHook.Entries, 2)
		firstEntry := p.logHook.Entries[0]
		p.Require().Equal(logrus.WarnLevel, firstEntry.Level)
		p.Require().Equal("Caller is no longer being watched", firstEntry.Message)
		secondEntry := p.logHook.Entries[1]
		p.Require().Equal(logrus.WarnLevel, secondEntry.Level)
		p.Require().Equal("Caller exit suspected due to failed readdirent", secondEntry.Message)
		p.Require().Equal(syscall.ENOENT, secondEntry.Data["error"])
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
func (f *fakeUDSPeer) connect(addr *net.UnixAddr, doneCh chan error) {
	if f.conn != nil {
		f.t.Fatal("fake peer already connected")
	}

	go func() {
		conn, err := net.DialUnix("unix", nil, addr)
		if err != nil {
			doneCh <- fmt.Errorf("could not dial unix address: %w", err)
			return
		}

		f.conn = conn
		doneCh <- nil
	}()
}

// close a connection we opened previously
func (f *fakeUDSPeer) disconnect() {
	if f.conn == nil {
		f.t.Fatal("fake peer not connected")
	}

	f.conn.Close()
	f.conn = nil
}

// run child to connect and fork. allows us to test stale PID data
func (f *fakeUDSPeer) connectFromForkingChild(addr *net.UnixAddr, childPath string, doneCh chan error) {
	if f.grandchildPID != 0 {
		f.t.Fatalf("grandchild already running with PID %v", f.grandchildPID)
	}

	go func() {
		out, err := exec.Command(childPath, "-socketPath", addr.Name).Output()
		if err != nil {
			doneCh <- fmt.Errorf("child process failed: %w", err)
			return
		}

		// Get and store the grandchild PID from our child's STDOUT
		grandchildPID, err := strconv.ParseInt(string(out), 10, 0)
		if err != nil {
			doneCh <- fmt.Errorf("could not get grandchild pid: %w", err)
			return
		}

		f.grandchildPID = int(grandchildPID)
		doneCh <- nil
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
