package log

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestRotatableFile returns a RotatableFile whose clock is driven by the
// returned pointer.
func newTestRotatableFile(t *testing.T, name string, cfg RotationConfig) (*RotatableFile, *time.Time) {
	t.Helper()

	rf, err := NewRotatableFile(name, cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = rf.Close()
	})

	now := time.Date(2026, 8, 18, 22, 43, 1, 0, time.Local)
	rf.now = func() time.Time { return now }
	return rf, &now
}

// backupNames returns the rotated files for logPath, newest first.
func backupNames(t *testing.T, logPath string) []string {
	t.Helper()

	dir := filepath.Dir(logPath)
	base := filepath.Base(logPath)
	ext := filepath.Ext(base)
	prefix := strings.TrimSuffix(base, ext) + "-"

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	var names []string
	for _, entry := range entries {
		if _, ok := timeFromName(entry.Name(), prefix, ext); ok {
			names = append(names, entry.Name())
		}
	}
	// Names embed a sortable timestamp, so lexical order is chronological.
	slices.Sort(names)
	slices.Reverse(names)
	return names
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}

func TestRotatableFileRotatesOnSize(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	rf, _ := newTestRotatableFile(t, logPath, RotationConfig{MaxSizeMB: 1})

	// fill the file to just under the limit
	chunk := []byte(strings.Repeat("a", 1024))
	for range mebibyte / 1024 {
		_, err := rf.Write(chunk)
		require.NoError(t, err)
	}
	assert.Empty(t, backupNames(t, logPath), "should not have rotated yet")

	// the next write crosses the limit
	_, err := rf.Write([]byte("trigger"))
	require.NoError(t, err)

	backups := backupNames(t, logPath)
	require.Len(t, backups, 1, "exactly one rotated file should exist")

	// the active file stays at the configured path with only the newest write
	assert.Equal(t, "trigger", readFile(t, logPath))
	assert.Len(t, readFile(t, filepath.Join(dir, backups[0])), mebibyte)
}

func TestRotatableFileDoesNotRotateOnOpen(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	// pre-existing content already past the limit
	require.NoError(t, os.WriteFile(logPath, []byte(strings.Repeat("a", 2*mebibyte)), 0600))

	rf, _ := newTestRotatableFile(t, logPath, RotationConfig{MaxSizeMB: 1})

	assert.Empty(t, backupNames(t, logPath), "opening must not rotate")

	// the existing size is accounted for, so the first write rotates
	_, err := rf.Write([]byte("first"))
	require.NoError(t, err)

	assert.Len(t, backupNames(t, logPath), 1)
	assert.Equal(t, "first", readFile(t, logPath))
}

func TestRotatableFileKeepsWriteLargerThanMaxSize(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	rf, _ := newTestRotatableFile(t, logPath, RotationConfig{MaxSizeMB: 1})

	// a single entry bigger than the limit is written intact rather than dropped
	huge := []byte(strings.Repeat("a", 2*mebibyte))
	n, err := rf.Write(huge)
	require.NoError(t, err)
	assert.Equal(t, len(huge), n)
	assert.Empty(t, backupNames(t, logPath), "rotating an empty file makes no progress")
	assert.Len(t, readFile(t, logPath), 2*mebibyte)

	// the oversized content is rotated away on the next write
	_, err = rf.Write([]byte("next"))
	require.NoError(t, err)
	assert.Len(t, backupNames(t, logPath), 1)
	assert.Equal(t, "next", readFile(t, logPath))
}

func TestRotatableFileReopenForcesRotation(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	rf, now := newTestRotatableFile(t, logPath, RotationConfig{})

	_, err := rf.Write([]byte("before"))
	require.NoError(t, err)

	// size based rotation is disabled, but SIGUSR2 still rotates
	require.NoError(t, rf.Reopen())

	backups := backupNames(t, logPath)
	require.Len(t, backups, 1)
	assert.Equal(t, "before", readFile(t, filepath.Join(dir, backups[0])))
	assert.Empty(t, readFile(t, logPath))

	*now = now.Add(time.Second)
	_, err = rf.Write([]byte("after"))
	require.NoError(t, err)
	assert.Equal(t, "after", readFile(t, logPath))
}

func TestRotatableFileReopenAfterExternalRename(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	rf, _ := newTestRotatableFile(t, logPath, RotationConfig{})

	_, err := rf.Write([]byte("before"))
	require.NoError(t, err)

	// emulate logrotate having already moved the file aside. Closed first
	// because Windows will not rename an open file, which also leaves rf.f
	// pointing at a closed descriptor for rotate() to tolerate.
	require.NoError(t, rf.Close())
	rotated := logPath + ".1"
	require.NoError(t, os.Rename(logPath, rotated))
	require.NoFileExists(t, logPath)

	require.NoError(t, rf.Reopen())
	assert.Empty(t, backupNames(t, logPath), "nothing to move aside")

	_, err = rf.Write([]byte("after"))
	require.NoError(t, err)
	assert.Equal(t, "after", readFile(t, logPath))
	assert.Equal(t, "before", readFile(t, rotated))
}

func TestRotatableFilePrunesByCount(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	rf, now := newTestRotatableFile(t, logPath, RotationConfig{MaxFiles: 2})

	for i := range 5 {
		_, err := rf.Write(fmt.Appendf(nil, "entry %d", i))
		require.NoError(t, err)
		require.NoError(t, rf.Reopen())
		*now = now.Add(time.Second)
	}

	backups := backupNames(t, logPath)
	require.Len(t, backups, 2, "only the newest rotated files are retained")

	// newest first
	assert.Equal(t, "entry 4", readFile(t, filepath.Join(dir, backups[0])))
	assert.Equal(t, "entry 3", readFile(t, filepath.Join(dir, backups[1])))
}

func TestRotatableFilePrunesByAge(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	rf, now := newTestRotatableFile(t, logPath, RotationConfig{MaxAgeDays: 2})

	// three rotations, a day apart
	for i := range 3 {
		_, err := rf.Write(fmt.Appendf(nil, "entry %d", i))
		require.NoError(t, err)
		require.NoError(t, rf.Reopen())
		*now = now.Add(24 * time.Hour)
	}
	assert.Len(t, backupNames(t, logPath), 3, "nothing is old enough yet")

	// move far enough forward that the two oldest fall outside the window
	*now = now.Add(24 * time.Hour)
	_, err := rf.Write([]byte("last"))
	require.NoError(t, err)
	require.NoError(t, rf.Reopen())

	backups := backupNames(t, logPath)
	require.Len(t, backups, 2)
	assert.Equal(t, "last", readFile(t, filepath.Join(dir, backups[0])))
	assert.Equal(t, "entry 2", readFile(t, filepath.Join(dir, backups[1])))
}

func TestRotatableFileLeavesUnrelatedFilesAlone(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	// files without a rotation timestamp must never be pruned
	unrelated := []string{
		filepath.Join(dir, "other.log"),
		filepath.Join(dir, "test.log.1"),
		filepath.Join(dir, "test-notatimestamp.log"),
	}
	for _, path := range unrelated {
		require.NoError(t, os.WriteFile(path, []byte("keep me"), 0600))
	}

	rf, now := newTestRotatableFile(t, logPath, RotationConfig{MaxFiles: 1, MaxAgeDays: 1})

	for i := range 3 {
		_, err := rf.Write(fmt.Appendf(nil, "entry %d", i))
		require.NoError(t, err)
		require.NoError(t, rf.Reopen())
		*now = now.Add(time.Second)
	}

	assert.Len(t, backupNames(t, logPath), 1)
	for _, path := range unrelated {
		assert.FileExists(t, path)
	}
}

func TestRotatableFileBackupNameCollision(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	// the clock never advances, so every rotation asks for the same name
	rf, _ := newTestRotatableFile(t, logPath, RotationConfig{})

	for i := range 3 {
		_, err := rf.Write(fmt.Appendf(nil, "entry %d", i))
		require.NoError(t, err)
		require.NoError(t, rf.Reopen())
	}

	backups := backupNames(t, logPath)
	assert.Len(t, backups, 3, "colliding names must not overwrite each other")

	contents := make([]string, 0, len(backups))
	for _, name := range backups {
		contents = append(contents, readFile(t, filepath.Join(dir, name)))
	}
	assert.ElementsMatch(t, []string{"entry 0", "entry 1", "entry 2"}, contents)
}

func TestRotatableFileRenameFailureKeepsWriting(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	rf, _ := newTestRotatableFile(t, logPath, RotationConfig{MaxSizeMB: 1})
	renameErr := errors.New("rename boom")
	rf.renameFunc = func(string, string) error { return renameErr }

	// Reopen surfaces the failure, which is how the signal handler reports it
	_, err := rf.Write([]byte("first"))
	require.NoError(t, err)
	require.ErrorIs(t, rf.Reopen(), renameErr)

	// nothing was lost and the file is still writable
	_, err = rf.Write([]byte("second"))
	require.NoError(t, err)
	assert.Equal(t, "firstsecond", readFile(t, logPath))
	assert.Empty(t, backupNames(t, logPath))

	// the clock is deliberately not advanced: the backoff only throttles the
	// Write path, not an explicit Reopen
	rf.renameFunc = os.Rename
	require.NoError(t, rf.Reopen())
	assert.Len(t, backupNames(t, logPath), 1)
}

func TestRotatableFileReopenIsNoOpWhenEmpty(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	rf, now := newTestRotatableFile(t, logPath, RotationConfig{MaxFiles: 1})

	_, err := rf.Write([]byte("real content"))
	require.NoError(t, err)
	require.NoError(t, rf.Reopen())

	backups := backupNames(t, logPath)
	require.Len(t, backups, 1)
	require.Equal(t, "real content", readFile(t, filepath.Join(dir, backups[0])))

	// a signal arriving while the service is idle must not spend the retention
	// budget on a zero byte file
	for range 3 {
		*now = now.Add(24 * time.Hour)
		require.NoError(t, rf.Reopen())
	}

	backups = backupNames(t, logPath)
	require.Len(t, backups, 1, "idle rotations must not create backups")
	assert.Equal(t, "real content", readFile(t, filepath.Join(dir, backups[0])),
		"idle rotations must not evict the backup holding real content")
}

func TestRotatableFileWriteRecoversAfterFailedRotation(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	rf, _ := newTestRotatableFile(t, logPath, RotationConfig{})

	_, err := rf.Write([]byte("before"))
	require.NoError(t, err)

	// emulate a rotation that closed the descriptor and then failed to reopen,
	// e.g. a transient ENOSPC. With size based rotation off nothing would call
	// rotate() again, so Write has to recover on its own.
	require.NoError(t, rf.Close())
	require.NoError(t, os.Remove(logPath))
	rf.f = nil

	n, err := rf.Write([]byte("after"))
	require.NoError(t, err, "Write should reopen the log rather than drop the line")
	assert.Equal(t, len("after"), n)
	assert.Equal(t, "after", readFile(t, logPath))
}

func TestRotatableFileBacksOffAfterFailure(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	rf, now := newTestRotatableFile(t, logPath, RotationConfig{MaxSizeMB: 1})

	var attempts int
	rf.renameFunc = func(string, string) error {
		attempts++
		return errors.New("rename boom")
	}

	// push the file over the limit so every subsequent write wants to rotate
	_, err := rf.Write([]byte(strings.Repeat("a", mebibyte)))
	require.NoError(t, err)

	for range 10 {
		_, err := rf.Write([]byte("x"))
		require.NoError(t, err)
	}
	assert.Equal(t, 1, attempts, "a failing rotation must not be retried on every write")

	// after the backoff window the writer tries again
	*now = now.Add(rotateRetryInterval)
	_, err = rf.Write([]byte("x"))
	require.NoError(t, err)
	assert.Equal(t, 2, attempts)
}

func TestRotatableFileIgnoresCloseFailure(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	rf, _ := newTestRotatableFile(t, logPath, RotationConfig{})
	rf.closeFunc = func(f *os.File) error {
		// still close it so the test does not leak a descriptor
		_ = f.Close()
		return errors.New("close boom")
	}

	_, err := rf.Write([]byte("before"))
	require.NoError(t, err)
	require.NoError(t, rf.Reopen(), "a close failure must not fail the rotation")
	assert.Len(t, backupNames(t, logPath), 1)
}

func TestRotatableFileWriteAfterUnusableRotation(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	rf, _ := newTestRotatableFile(t, logPath, RotationConfig{})

	_, err := rf.Write([]byte("before"))
	require.NoError(t, err)

	// remove the directory so the post-rotation open cannot succeed
	require.NoError(t, rf.Close())
	require.NoError(t, os.RemoveAll(dir))

	require.Error(t, rf.Reopen(), "rotation should report that it could not reopen")

	// the writer reports the problem rather than panicking on a nil file
	_, err = rf.Write([]byte("after"))
	require.Error(t, err)
}

func TestRotatableFileConcurrentWrites(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	rf, err := NewRotatableFile(logPath, RotationConfig{MaxSizeMB: 1, MaxFiles: 10})
	require.NoError(t, err)
	defer func() {
		_ = rf.Close()
	}()

	const (
		writers = 8
		writes  = 200
	)
	line := []byte(strings.Repeat("a", 1024) + "\n")

	var wg sync.WaitGroup
	for range writers {
		wg.Go(func() {
			for range writes {
				if _, err := rf.Write(line); err != nil {
					assert.NoError(t, err)
					return
				}
			}
		})
	}
	wg.Wait()

	// every byte must be accounted for across the active file and its siblings
	total := len(readFile(t, logPath))
	for _, name := range backupNames(t, logPath) {
		total += len(readFile(t, filepath.Join(dir, name)))
	}
	assert.Equal(t, writers*writes*len(line), total)
}

func TestRotatableFileName(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	rf, _ := newTestRotatableFile(t, logPath, RotationConfig{})
	assert.Equal(t, logPath, rf.Name())
}

func TestRotatableFileWithLogger(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	rf, _ := newTestRotatableFile(t, logPath, RotationConfig{})

	logger, err := NewLogger(WithReopenableOutputFile(rf), WithFormat(TextFormat))
	require.NoError(t, err)

	logger.Warning("before rotation")
	require.NoError(t, rf.Reopen())
	logger.Warning("after rotation")

	backups := backupNames(t, logPath)
	require.Len(t, backups, 1)
	assert.Contains(t, readFile(t, filepath.Join(dir, backups[0])), "before rotation")

	current := readFile(t, logPath)
	assert.Contains(t, current, "after rotation")
	assert.NotContains(t, current, "before rotation")
}

func TestRotationConfigValidate(t *testing.T) {
	for _, tt := range []struct {
		desc   string
		cfg    RotationConfig
		expect string
	}{
		{
			desc: "empty is valid",
			cfg:  RotationConfig{},
		},
		{
			desc: "all set is valid",
			cfg:  RotationConfig{MaxSizeMB: 1, MaxFiles: 2, MaxAgeDays: 3},
		},
		{
			desc:   "negative max_size_mb",
			cfg:    RotationConfig{MaxSizeMB: -1},
			expect: "max_size_mb (-1) must not be negative",
		},
		{
			desc:   "max_size_mb beyond the overflow guard",
			cfg:    RotationConfig{MaxSizeMB: maxSizeMBLimit + 1},
			expect: "max_size_mb (1048577) must not be greater than 1048576",
		},
		{
			desc: "max_size_mb at the limit is valid",
			cfg:  RotationConfig{MaxSizeMB: maxSizeMBLimit},
		},
		{
			desc:   "negative max_files",
			cfg:    RotationConfig{MaxFiles: -1},
			expect: "max_files (-1) must not be negative",
		},
		{
			desc:   "negative max_age_days",
			cfg:    RotationConfig{MaxAgeDays: -1},
			expect: "max_age_days (-1) must not be negative",
		},
		{
			desc:   "max_age_days beyond the overflow guard",
			cfg:    RotationConfig{MaxAgeDays: maxAgeDaysLimit + 1},
			expect: "max_age_days (36501) must not be greater than 36500",
		},
		{
			desc: "max_age_days at the limit is valid",
			cfg:  RotationConfig{MaxAgeDays: maxAgeDaysLimit},
		},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.expect == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tt.expect)
		})
	}
}

func TestRotationConfigIsZero(t *testing.T) {
	assert.True(t, RotationConfig{}.IsZero())
	assert.False(t, RotationConfig{MaxSizeMB: 1}.IsZero())
	assert.False(t, RotationConfig{MaxFiles: 1}.IsZero())
	assert.False(t, RotationConfig{MaxAgeDays: 1}.IsZero())
}

func TestNewRotatableFileRejectsInvalidConfig(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	_, err := NewRotatableFile(logPath, RotationConfig{MaxSizeMB: -1})
	require.EqualError(t, err, "max_size_mb (-1) must not be negative")
	assert.NoFileExists(t, logPath, "an invalid config must not create the log file")
}
