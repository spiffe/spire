//go:build linux

package peertracker

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"golang.org/x/sys/unix"
)

const (
	linuxType = "linux"
)

type linuxTracker struct {
	log              logrus.FieldLogger
	allowUIDMismatch bool
}

func newTrackerWithConfig(log logrus.FieldLogger, config TrackerConfig) (*linuxTracker, error) {
	return &linuxTracker{
		log:              log.WithField(telemetry.Type, linuxType),
		allowUIDMismatch: config.AllowUIDMismatch,
	}, nil
}

func newTracker(log logrus.FieldLogger) (*linuxTracker, error) {
	return newTrackerWithConfig(log, TrackerConfig{})
}

func (l *linuxTracker) NewWatcher(info CallerInfo) (Watcher, error) {
	return newLinuxWatcher(info, l.log, l.allowUIDMismatch)
}

func (*linuxTracker) Close() {
}

type linuxWatcher struct {
	gid              uint32
	pid              int32
	mtx              sync.Mutex
	procPath         string
	procfd           int
	starttime        string
	uid              uint32
	allowUIDMismatch bool
	log              logrus.FieldLogger
}

func newLinuxWatcher(info CallerInfo, log logrus.FieldLogger, allowUIDMismatch bool) (*linuxWatcher, error) {
	// If PID == 0, something is wrong...
	if info.PID == 0 {
		return nil, errors.New("could not resolve caller information")
	}

	procPath := fmt.Sprintf("/proc/%v", info.PID)

	// Grab a handle to proc first since that's the fastest thing we can do
	procfd, err := unix.Open(procPath, unix.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("could not open caller's proc directory: %w", err)
	}

	starttime, err := getStarttime(info.PID)
	if err != nil {
		unix.Close(procfd)
		return nil, err
	}

	log = log.WithFields(logrus.Fields{
		telemetry.CallerGID: info.GID,
		telemetry.PID:       info.PID,
		telemetry.Path:      procPath,
		telemetry.CallerUID: info.UID,
		telemetry.StartTime: starttime,
	})

	return &linuxWatcher{
		gid:              info.GID,
		pid:              info.PID,
		procPath:         procPath,
		procfd:           procfd,
		starttime:        starttime,
		uid:              info.UID,
		allowUIDMismatch: allowUIDMismatch,
		log:              log,
	}, nil
}

func (l *linuxWatcher) Close() {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	if l.procfd < 0 {
		return
	}

	unix.Close(l.procfd)
	l.procfd = -1
}

func (l *linuxWatcher) IsAlive() error {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	if l.procfd < 0 {
		l.log.Warn("Caller is no longer being watched")
		return errors.New("caller is no longer being watched")
	}

	// First we will check if we can read from the original directory handle.
	// If the process has exited since we opened it, the read should fail (i.e.
	// the ReadDirent syscall will return -1)
	var buf [8196]byte
	n, err := unix.ReadDirent(l.procfd, buf[:])
	if err != nil {
		l.log.WithError(err).Warn("Caller exit suspected due to failed readdirent")
		return errors.New("caller exit suspected due to failed readdirent")
	}
	if n < 0 {
		l.log.WithField(telemetry.StatusCode, n).Warn("Caller exit suspected due to failed readdirent")
		return fmt.Errorf("caller exit suspected due to failed readdirent: n=%d", n)
	}

	// A successful fd read should indicate that the original process is still alive, however
	// it is not clear if the original inode can be freed by Linux while it is still referenced.
	// This _shouldn't_ happen, but if it does, then there might be room for a reused PID to
	// collide with the original inode making the read successful. As an extra measure, ensure
	// that the current `starttime` matches the one we saw originally.
	//
	// This is probably overkill.
	// TODO: Evaluate the use of `starttime` as the primary exit detection mechanism.
	currentStarttime, err := getStarttime(l.pid)
	if err != nil {
		l.log.WithError(err).Warn("Caller exit suspected due to failure to get starttime")
		return fmt.Errorf("caller exit suspected due to failure to get starttime: %w", err)
	}
	if currentStarttime != l.starttime {
		l.log.WithFields(logrus.Fields{
			telemetry.ExpectStartTime:   l.starttime,
			telemetry.ReceivedStartTime: currentStarttime,
		}).Warn("New process detected: process starttime does not match original caller")
		return fmt.Errorf("new process detected: process starttime %v does not match original caller %v", currentStarttime, l.starttime)
	}

	// Finally, read the UID and GID off the proc directory to determine the owner. If
	// we got beaten by a PID race when opening the proc handle originally, we can at
	// least get to know that the race winner is running as the same user and group as
	// the original caller by comparing it to the received CallerInfo.
	var stat unix.Stat_t
	if err := unix.Stat(l.procPath, &stat); err != nil {
		l.log.WithError(err).Warn("Caller exit suspected due to failed proc stat")
		return errors.New("caller exit suspected due to failed proc stat")
	}
	if err := l.checkUID(stat.Uid); err != nil {
		return err
	}
	if err := l.checkGID(stat.Gid); err != nil {
		return err
	}

	return nil
}

// checkUID verifies that the process UID (as reported by stat on /proc/<pid>)
// matches the caller UID from SO_PEERCRED. When they differ the mismatch is
// resolved through a two-layer check:
//
//  1. User-namespace remapping: translate the host UID back through
//     /proc/<pid>/uid_map. Handles rootless containers transparently,
//     with no configuration required.
//  2. CAP_SETUID (when allow_uid_mismatch is true): if the process holds
//     CAP_SETUID in its effective capability set it can legitimately forge
//     SO_PEERCRED credentials (as gVisor/runsc does with --host-uds=open).
//     The connection is allowed with a warning log.
func (l *linuxWatcher) checkUID(statUID uint32) error {
	return l.checkUIDWith(
		statUID,
		readIDMap(l.pid, "uid_map"),
		l.allowUIDMismatch && processHasCapability(l.pid, capSetUID),
	)
}

// checkUIDWith is the testable core of checkUID. It accepts the uid_map
// content and whether the CAP_SETUID allowance applies as parameters so
// unit tests can exercise every branch without a live /proc filesystem.
func (l *linuxWatcher) checkUIDWith(statUID uint32, uidMapContent string, allowMismatch bool) error {
	if statUID == l.uid {
		return nil
	}

	// Layer 1: user-namespace UID remapping.
	// /proc/<pid>/uid_map maps namespace-internal UIDs to host UIDs:
	//   <ns_start> <host_start> <count>
	// stat() on /proc/<pid> already returns the host-translated UID, so if
	// the uid_map shows that the host UID translates back to the expected
	// caller UID we can accept the connection.
	if nsUID, ok := lookupIDInMap(uidMapContent, statUID); ok && nsUID == l.uid {
		return nil
	}

	// Layer 2: CAP_SETUID in the process effective capability set.
	// Enabled only when allow_uid_mismatch is configured. A process that
	// holds CAP_SETUID can forge SO_PEERCRED credentials on a Unix domain
	// socket (this is exactly what the gVisor gofer does under --host-uds).
	// If the flag is set and the process has the capability the mismatch is
	// expected; allow it while maintaining the ReadDirent + starttime
	// TOCTOU safeguards.
	if allowMismatch {
		l.log.WithFields(logrus.Fields{
			telemetry.ExpectUID:   l.uid,
			telemetry.ReceivedUID: statUID,
		}).Warn("Process uid does not match original caller; allowing because allow_uid_mismatch is set and process holds CAP_SETUID")
		return nil
	}

	l.log.WithFields(logrus.Fields{
		telemetry.ExpectUID:   l.uid,
		telemetry.ReceivedUID: statUID,
	}).Warn("New process detected: process uid does not match original caller")
	return fmt.Errorf("new process detected: process uid %v does not match original caller %v", statUID, l.uid)
}

// checkGID is the GID analogue of checkUID. It checks CAP_SETGID instead of
// CAP_SETUID.
func (l *linuxWatcher) checkGID(statGID uint32) error {
	return l.checkGIDWith(
		statGID,
		readIDMap(l.pid, "gid_map"),
		l.allowUIDMismatch && processHasCapability(l.pid, capSetGID),
	)
}

// checkGIDWith is the testable core of checkGID.
func (l *linuxWatcher) checkGIDWith(statGID uint32, gidMapContent string, allowMismatch bool) error {
	if statGID == l.gid {
		return nil
	}

	if nsGID, ok := lookupIDInMap(gidMapContent, statGID); ok && nsGID == l.gid {
		return nil
	}

	if allowMismatch {
		l.log.WithFields(logrus.Fields{
			telemetry.ExpectGID:   l.gid,
			telemetry.ReceivedGID: statGID,
		}).Warn("Process gid does not match original caller; allowing because allow_uid_mismatch is set and process holds CAP_SETGID")
		return nil
	}

	l.log.WithFields(logrus.Fields{
		telemetry.ExpectGID:   l.gid,
		telemetry.ReceivedGID: statGID,
	}).Warn("New process detected: process gid does not match original caller")
	return fmt.Errorf("new process detected: process gid %v does not match original caller %v", statGID, l.gid)
}

// readIDMap reads /proc/<pid>/uid_map or gid_map and returns its contents.
// Returns an empty string on any read error.
func readIDMap(pid int32, mapFile string) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, mapFile))
	if err != nil {
		return ""
	}
	return string(data)
}

// lookupIDInMap parses a /proc/<pid>/uid_map or gid_map file and translates
// a host ID to its namespace-internal counterpart.
//
// Each line has the form:  <ns_start>  <host_start>  <count>
// meaning: IDs [host_start, host_start+count) on the host map to
//          [ns_start, ns_start+count) inside the namespace.
//
// Returns (nsID, true) when hostID falls within a mapped range, (0, false)
// otherwise.
func lookupIDInMap(content string, hostID uint32) (uint32, bool) {
	for _, line := range strings.Split(strings.TrimSpace(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var nsStart, hostStart, count uint32
		if _, err := fmt.Sscanf(line, "%d %d %d", &nsStart, &hostStart, &count); err != nil {
			continue
		}
		if count == 0 {
			continue
		}
		if hostID >= hostStart && hostID < hostStart+count {
			return nsStart + (hostID - hostStart), true
		}
	}
	return 0, false
}

// Linux capability numbers relevant to credential forging.
const (
	capSetGID = 6 // CAP_SETGID
	capSetUID = 7 // CAP_SETUID
)

// processHasCapability reports whether the process with the given PID holds
// the specified capability in its effective capability set (CapEff) as
// reported by /proc/<pid>/status.
//
// Returns false on any read or parse error so that callers fall through to
// the next check rather than silently allowing connections.
func processHasCapability(pid int32, cap uint) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}
	return parseCapEff(string(data), cap)
}

// parseCapEff parses the content of a /proc/<pid>/status file and checks
// whether the given capability bit is set in the CapEff field.
//
// The CapEff field is a hex-encoded 64-bit bitmask; capability N corresponds
// to bit N (0-indexed from the LSB).
//
// Returns false if the field is absent or unparseable.
func parseCapEff(content string, cap uint) bool {
	for _, line := range strings.Split(content, "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return false
		}
		capEff, err := strconv.ParseUint(fields[1], 16, 64)
		if err != nil {
			return false
		}
		return capEff&(1<<cap) != 0
	}
	return false
}

func (l *linuxWatcher) PID() int32 {
	return l.pid
}

func parseTaskStat(stat string) ([]string, error) {
	b := strings.IndexByte(stat, '(')
	e := strings.LastIndexByte(stat, ')')
	if b == -1 || e == -1 {
		return nil, errors.New("task name is not parenthesized")
	}

	fields := make([]string, 0, 52)
	fields = append(fields, strings.Split(stat[:b-1], " ")...)
	fields = append(fields, stat[b+1:e])
	fields = append(fields, strings.Split(stat[e+2:], " ")...)
	return fields, nil
}

func getStarttime(pid int32) (string, error) {
	statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%v/stat", pid))
	if err != nil {
		return "", fmt.Errorf("could not read caller stat: %w", err)
	}

	statFields, err := parseTaskStat(string(statBytes))
	if err != nil {
		return "", fmt.Errorf("bad stat data: %w", err)
	}

	// starttime is the 22nd field in the proc stat data
	// Field number 38 was introduced in Linux 2.1.22
	// Protect against invalid index and reject anything before 2.1.22
	if len(statFields) < 38 {
		return "", errors.New("bad stat data or unsupported platform")
	}

	return statFields[21], nil
}
