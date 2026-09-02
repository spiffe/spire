package log

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/hcl/hcl/token"
)

const (
	// backupTimeFormat is the local time encoded into rotated file names. It
	// sorts lexically and avoids characters that are illegal on Windows.
	backupTimeFormat = "2006-01-02T15-04-05.000"

	mebibyte = 1024 * 1024

	// Applied when a key is left unset, so that a bare block is bounded.
	defaultMaxSizeMB = 100
	defaultMaxFiles  = 7

	// Upper bound that keeps the conversion to bytes clear of overflow.
	maxSizeMBLimit = 1024 * 1024

	// rotateRetryInterval throttles retries so a persistent failure does not
	// attempt a rename for every line written.
	rotateRetryInterval = time.Minute
)

var _ ReopenableWriteCloser = (*RotatableFile)(nil)

// RotationConfig configures rotation and retention. It doubles as the HCL shape
// of the log_file_rotation block. A key left unset takes a default, so a block
// with no keys still rotates; an explicit 0 turns that bound off.
type RotationConfig struct {
	// MaxSizeMB is the size the log file may reach before it is rotated.
	// Explicitly 0 disables size based rotation, leaving it to Reopen.
	MaxSizeMB *int `hcl:"max_size_mb"`

	// MaxFiles is how many rotated files to retain, not counting the active
	// one. Explicitly 0 retains all of them.
	MaxFiles *int `hcl:"max_files"`

	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`
}

func (c RotationConfig) maxSizeMB() int {
	if c.MaxSizeMB == nil {
		return defaultMaxSizeMB
	}
	return *c.MaxSizeMB
}

func (c RotationConfig) maxFiles() int {
	if c.MaxFiles == nil {
		return defaultMaxFiles
	}
	return *c.MaxFiles
}

// SizeRotationDisabled reports whether nothing will rotate the file on its own,
// leaving it to an explicit Reopen.
func (c RotationConfig) SizeRotationDisabled() bool {
	return c.maxSizeMB() == 0
}

func (c RotationConfig) Validate() error {
	if c.MaxSizeMB != nil {
		switch {
		case *c.MaxSizeMB < 0:
			return fmt.Errorf("max_size_mb (%d) must not be negative", *c.MaxSizeMB)
		case *c.MaxSizeMB > maxSizeMBLimit:
			return fmt.Errorf("max_size_mb (%d) must not be greater than %d", *c.MaxSizeMB, maxSizeMBLimit)
		}
	}
	if c.MaxFiles != nil && *c.MaxFiles < 0 {
		return fmt.Errorf("max_files (%d) must not be negative", *c.MaxFiles)
	}
	return nil
}

// NewOutputFile opens the log file, returning a RotatableFile when cfg asks for
// rotation and a ReopenableFile otherwise. A nil cfg means no rotation.
func NewOutputFile(name string, cfg *RotationConfig) (ReopenableWriteCloser, error) {
	// Returned explicitly rather than passed through, so that a failure yields
	// a nil interface instead of one wrapping a nil pointer.
	if cfg == nil {
		f, err := NewReopenableFile(name)
		if err != nil {
			return nil, err
		}
		return f, nil
	}
	f, err := NewRotatableFile(name, *cfg)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// RotatableFile rotates the log file in process rather than relying on an
// external tool. An external tool can move the file aside on any platform, but
// only POSIX has a way to then tell SPIRE to start a new one.
//
// The active file always stays at the configured path; rotation moves the
// accumulated content aside to a timestamped sibling.
type RotatableFile struct {
	name string
	cfg  RotationConfig

	mu sync.Mutex
	f  *os.File
	// size is seeded from disk so content written before this process started,
	// or removed by an external copytruncate, is accounted for.
	size int64
	// rotateFailedAt is zero unless the last rotation attempt failed, and
	// rotateErr carries that failure until something reports it.
	rotateFailedAt time.Time
	rotateErr      error

	// now, closeFunc and renameFunc are intended for injecting errors and a
	// fake clock under test. closeFunc and renameFunc must be called while
	// holding the lock.
	now        func() time.Time
	closeFunc  closeFunc
	renameFunc func(oldpath, newpath string) error
}

// NewRotatableFile opens name for appending. It does not rotate on open, even
// if the file already exceeds MaxSizeMB.
func NewRotatableFile(name string, cfg RotationConfig) (*RotatableFile, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	r := &RotatableFile{
		name:       name,
		cfg:        cfg,
		now:        time.Now,
		closeFunc:  func(f *os.File) error { return f.Close() },
		renameFunc: os.Rename,
	}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

// Write rotates first if this write would take the file past MaxSizeMB. A
// failed rotation is not returned: logrus hands this writer to plugins as a
// bare io.Writer, and reporting through the logger would re-enter logrus while
// it holds its own lock. The write is attempted regardless, so a failure costs
// an oversized file rather than a lost line. Reopen surfaces the error.
func (r *RotatableFile) Write(b []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.shouldRotate(int64(len(b))) {
		_ = r.rotateAndRecord()
	}

	// An earlier rotation failed after closing the descriptor. Reopen rather
	// than drop this line and every line after it, ignoring the backoff since
	// the point is to restore logging, not to rotate.
	if r.f == nil {
		if err := r.open(); err != nil {
			return 0, err
		}
	}

	n, err = r.f.Write(b)
	r.size += int64(n)
	return n, err
}

// Reopen forces an immediate rotation. It is what the signal handler calls.
func (r *RotatableFile) Reopen() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.rotateAndRecord()
}

func (r *RotatableFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.f == nil {
		return nil
	}
	return r.f.Close()
}

// Name implements part of os.FileInfo without needing a lock on the underlying
// file.
func (r *RotatableFile) Name() string {
	return r.name
}

// open opens the configured path and reseeds size from disk. It must be called
// while holding the lock, except from the constructor.
func (r *RotatableFile) open() error {
	file, err := openLogFile(r.name)
	if err != nil {
		return err
	}
	r.f = file

	// A failure here only means the next rotation happens a little late.
	r.size = 0
	if info, err := file.Stat(); err == nil {
		r.size = info.Size()
	}
	return nil
}

// rotateAndRecord must be called while holding the lock.
func (r *RotatableFile) rotateAndRecord() error {
	err := r.rotate()
	if err != nil {
		r.rotateFailedAt = r.now()
		r.rotateErr = err
	} else {
		r.rotateFailedAt = time.Time{}
	}
	return err
}

// TakeRotateError returns the last rotation failure and clears it. Write cannot
// report one itself, since logrus hands this writer to plugins as a bare
// io.Writer and logging from inside it would re-enter logrus while it holds its
// own lock. Something outside the writer has to drain this.
func (r *RotatableFile) TakeRotateError() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	err := r.rotateErr
	r.rotateErr = nil
	return err
}

// shouldRotate must be called while holding the lock.
func (r *RotatableFile) shouldRotate(writeLen int64) bool {
	maxSize := int64(r.cfg.maxSizeMB()) * mebibyte
	if maxSize <= 0 {
		return false
	}
	// Rotating an empty file makes no progress, which matters when a single
	// write is larger than the limit. Such a write is kept whole instead.
	if r.size == 0 {
		return false
	}
	if r.size+writeLen <= maxSize {
		return false
	}
	if !r.rotateFailedAt.IsZero() && r.now().Sub(r.rotateFailedAt) < rotateRetryInterval {
		return false
	}
	return true
}

// rotate must be called while holding the lock. The rename happens before the
// old descriptor is closed, so a failed rename leaves the writer untouched.
func (r *RotatableFile) rotate() error {
	// Rotating an empty file would spend the retention budget on a zero byte
	// file and evict one holding real content. Reopen is driven by a signal
	// SPIRE does not control, so a nightly rotation of an idle log is a no-op.
	// The size comes from disk so an external truncation is honored too.
	if r.f != nil {
		if info, err := os.Stat(r.name); err == nil && info.Size() == 0 {
			r.size = 0
			r.prune()
			return nil
		}
	}

	if err := r.renameCurrent(); err != nil {
		return err
	}

	old := r.f
	if err := r.open(); err != nil {
		// The old descriptor still works, it just writes into the file that was
		// moved aside. Keeping it loses less than dropping it.
		r.f = old
		return fmt.Errorf("unable to open %s after rotating: %w", r.name, err)
	}

	// Ignore errors closing the old descriptor since it has been replaced.
	if old != nil {
		_ = r.closeFunc(old)
	}

	r.prune()
	return nil
}

// renameCurrent moves the active file aside. A file that no longer exists is
// not an error: an external rotator may already have moved it, in which case
// rotation degrades to reopening the path.
func (r *RotatableFile) renameCurrent() error {
	if _, err := os.Stat(r.name); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("unable to stat %s before rotating: %w", r.name, err)
	}

	backup, err := r.backupName()
	if err != nil {
		return err
	}
	if err := r.renameFunc(r.name, backup); err != nil {
		return fmt.Errorf("unable to rotate %s: %w", r.name, err)
	}
	return nil
}

// backupName picks a free name. Two rotations in the same millisecond would
// otherwise collide, and renaming onto an existing file is not guaranteed to
// succeed on Windows.
func (r *RotatableFile) backupName() (string, error) {
	dir := filepath.Dir(r.name)
	prefix, ext := r.prefixAndExt()

	t := r.now()
	for range 1000 {
		candidate := filepath.Join(dir, prefix+t.Format(backupTimeFormat)+ext)
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate, nil
		}
		t = t.Add(time.Millisecond)
	}
	return "", fmt.Errorf("unable to find an unused rotated file name for %s", r.name)
}

// prefixAndExt splits the base name, so that "server.log" rotates to
// "server-<timestamp>.log".
func (r *RotatableFile) prefixAndExt() (prefix, ext string) {
	base := filepath.Base(r.name)
	ext = filepath.Ext(base)
	return strings.TrimSuffix(base, ext) + "-", ext
}

// prune removes rotated files outside the retention limits. It must be called
// while holding the lock. Errors are ignored since retention must not interfere
// with logging.
func (r *RotatableFile) prune() {
	maxFiles := r.cfg.maxFiles()
	if maxFiles <= 0 {
		return
	}

	backups := r.oldLogFiles()
	if len(backups) <= maxFiles {
		return
	}
	for _, b := range backups[maxFiles:] {
		_ = os.Remove(b.path)
	}
}

type backupFile struct {
	path      string
	timestamp time.Time
}

// oldLogFiles returns the rotated files for this log, newest first. Files
// without a parseable timestamp are ignored so unrelated files sharing the
// directory are never removed.
func (r *RotatableFile) oldLogFiles() []backupFile {
	dir := filepath.Dir(r.name)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	prefix, ext := r.prefixAndExt()

	var backups []backupFile
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ts, ok := timeFromName(entry.Name(), prefix, ext)
		if !ok {
			continue
		}
		backups = append(backups, backupFile{
			path:      filepath.Join(dir, entry.Name()),
			timestamp: ts,
		})
	}

	slices.SortFunc(backups, func(a, b backupFile) int {
		return b.timestamp.Compare(a.timestamp)
	})
	return backups
}

func timeFromName(name, prefix, ext string) (time.Time, bool) {
	// Keeps the slice in range if the prefix and extension were to overlap. A
	// panic here would be raised from inside a log write.
	if len(name) < len(prefix)+len(ext) {
		return time.Time{}, false
	}
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ext) {
		return time.Time{}, false
	}
	stamp := name[len(prefix) : len(name)-len(ext)]
	// Parsed local because that is how it was formatted. Around a DST fall back
	// the same name can describe two instants, which is immaterial to retention
	// measured in days.
	ts, err := time.ParseInLocation(backupTimeFormat, stamp, time.Local)
	if err != nil {
		return time.Time{}, false
	}
	return ts, true
}
