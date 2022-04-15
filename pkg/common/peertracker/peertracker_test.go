package peertracker

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"

	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

type peertrackerTest struct {
	childPath string
	listener  *Listener
	addr      net.Addr
	logHook   *logtest.Hook
}

func setupTest(t *testing.T) *peertrackerTest {
	childPath := filepath.Join(t.TempDir(), "child.exe")
	buildOutput, err := exec.Command("go", "build", "-o", childPath, childSource).CombinedOutput()
	if err != nil {
		t.Logf("build output:\n%v\n", string(buildOutput))
		require.FailNow(t, "failed to build test child")
	}

	log, logHook := logtest.NewNullLogger()

	listener := listener(t, log, addr(t))
	p := &peertrackerTest{
		childPath: childPath,
		listener:  listener,
		addr:      listener.Addr(),
		logHook:   logHook,
	}
	t.Cleanup(func() {
		if p.listener != nil {
			require.NoError(t, p.listener.Close())
		}
	})

	return p
}

func TestTrackerClose(t *testing.T) {
	test := setupTest(t)

	test.listener.Tracker.Close()
	_, err := test.listener.Tracker.NewWatcher(CallerInfo{})
	require.Error(t, err)
}

func TestListener(t *testing.T) {
	test := setupTest(t)

	doneCh := make(chan error)
	peer := newFakePeer(t)

	peer.connect(test.addr, doneCh)

	rawConn, err := test.listener.Accept()
	require.NoError(t, err)

	// Unblock connect goroutine
	require.NoError(t, <-doneCh)

	conn, ok := rawConn.(*Conn)
	require.True(t, ok)

	// Ensure we resolved the PID ok
	require.Equal(t, int32(os.Getpid()), conn.Info.Caller.PID)

	// Ensure watcher is set up correctly
	require.NotNil(t, conn.Info.Watcher)
	require.Equal(t, int32(os.Getpid()), conn.Info.Watcher.PID())

	peer.disconnect()
	conn.Close()
}

func TestExitDetection(t *testing.T) {
	test := setupTest(t)

	// First, just test against ourselves
	doneCh := make(chan error)
	peer := newFakePeer(t)

	peer.connect(test.addr, doneCh)

	rawConn, err := test.listener.Accept()
	require.NoError(t, err)

	// Unblock connect goroutine
	require.NoError(t, <-doneCh)

	conn, ok := rawConn.(*Conn)
	require.True(t, ok)

	// We're connected to ourselves - we should be alive!
	require.NoError(t, conn.Info.Watcher.IsAlive())

	// Should return an error once we're no longer tracking
	peer.disconnect()
	conn.Close()
	require.EqualError(t, conn.Info.Watcher.IsAlive(), "caller is no longer being watched")

	// Start a forking child and allow it to exit while the grandchild holds the socket
	peer.connectFromForkingChild(t, test.addr, test.childPath, doneCh)

	rawConn, err = test.listener.Accept()

	// Unblock child connect goroutine
	require.NoError(t, <-doneCh)

	// Check for Accept() error only after unblocking
	// the child so we can be sure that we can
	// clean up correctly
	defer peer.killGrandchild()
	require.NoError(t, err)

	conn, ok = rawConn.(*Conn)
	require.True(t, ok)

	// We know the child has exited because we read from doneCh
	// Call to IsAlive should now return an error
	switch runtime.GOOS {
	case "darwin":
		require.EqualError(t, conn.Info.Watcher.IsAlive(), "caller exit detected via kevent notification")
		require.Len(t, test.logHook.Entries, 2)
		firstEntry := test.logHook.Entries[0]
		require.Equal(t, logrus.WarnLevel, firstEntry.Level)
		require.Equal(t, "Caller is no longer being watched", firstEntry.Message)
		secondEntry := test.logHook.Entries[1]
		require.Equal(t, logrus.WarnLevel, secondEntry.Level)
		require.Equal(t, "Caller exit detected via kevent notification", secondEntry.Message)
	case "linux":
		require.EqualError(t, conn.Info.Watcher.IsAlive(), "caller exit suspected due to failed readdirent")
		require.Len(t, test.logHook.Entries, 2)
		firstEntry := test.logHook.Entries[0]
		require.Equal(t, logrus.WarnLevel, firstEntry.Level)
		require.Equal(t, "Caller is no longer being watched", firstEntry.Message)
		secondEntry := test.logHook.Entries[1]
		require.Equal(t, logrus.WarnLevel, secondEntry.Level)
		require.Equal(t, "Caller exit suspected due to failed readdirent", secondEntry.Message)
		require.Equal(t, syscall.ENOENT, secondEntry.Data["error"])
	case "windows":
		require.EqualError(t, conn.Info.Watcher.IsAlive(), "caller exit detected: exit code: 0")
		require.Len(t, test.logHook.Entries, 2)
		firstEntry := test.logHook.Entries[0]
		require.Equal(t, logrus.WarnLevel, firstEntry.Level)
		require.Equal(t, "Caller is no longer being watched", firstEntry.Message)
		secondEntry := test.logHook.Entries[1]
		require.Equal(t, logrus.WarnLevel, secondEntry.Level)
		require.Equal(t, "Caller is not running anymore", secondEntry.Message)
		require.Equal(t, "caller exit detected: exit code: 0", fmt.Sprintf("%v", secondEntry.Data["error"]))
	default:
		require.FailNow(t, "missing case for OS specific failure")
	}

	// Read a bit of data from our grandchild just to be sure it's still there
	theSign := make([]byte, 10)
	expectedSign := []byte("i'm alive!")
	_, err = conn.Read(theSign)
	require.NoError(t, err)
	require.Equal(t, expectedSign, theSign)

	conn.Close()

	// Check that IsAlive doesn't freak out if called after
	// the tracker has been closed
	test.listener.Close()
	test.listener = nil
	require.EqualError(t, conn.Info.Watcher.IsAlive(), "caller is no longer being watched")
}

func newFakePeer(t *testing.T) *fakePeer {
	return &fakePeer{
		t: t,
	}
}

// connect to the tcp listener
func (f *fakePeer) connect(addr net.Addr, doneCh chan error) {
	if f.conn != nil {
		f.t.Fatal("fake peer already connected")
	}

	go func() {
		conn, err := dial(addr)
		if err != nil {
			doneCh <- fmt.Errorf("could not dial address %s: %w", addr, err)
			return
		}

		f.conn = conn
		doneCh <- nil
	}()
}

// close a connection we opened previously
func (f *fakePeer) disconnect() {
	if f.conn == nil {
		f.t.Fatal("fake peer not connected")
	}

	f.conn.Close()
	f.conn = nil
}

// run child to connect and fork. allows us to test stale PID data
func (f *fakePeer) connectFromForkingChild(t *testing.T, addr net.Addr, childPath string, doneCh chan error) {
	if f.grandchildPID != 0 {
		f.t.Fatalf("grandchild already running with PID %v", f.grandchildPID)
	}

	go func() {
		// #nosec G204 test code
		out, err := childExecCommand(t, childPath, addr).Output()
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
