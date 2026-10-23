//go:build linux

package peertracker

import (
	"errors"
	"io"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookupIDInMap(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		hostID   uint32
		wantID   uint32
		wantOK   bool
	}{
		{
			name: "identity mapping — host root maps to ns 0",
			// gVisor's uid_map: maps entire range 1:1
			content: "0 0 4294967295\n",
			hostID:  0,
			wantID:  0,
			wantOK:  true,
		},
		{
			name: "identity mapping — arbitrary uid",
			content: "0 0 4294967295\n",
			hostID:  1000,
			wantID:  1000,
			wantOK:  true,
		},
		{
			name: "remapped uid — user namespace shifts by 100000",
			// ns 0 starts at host 100000, count 65536
			content: "0 100000 65536\n",
			hostID:  100000,
			wantID:  0,
			wantOK:  true,
		},
		{
			name: "remapped uid — mid-range lookup",
			content: "0 100000 65536\n",
			hostID:  100500,
			wantID:  500,
			wantOK:  true,
		},
		{
			name: "multi-line map — matched in second range",
			content: "0 100000 1000\n1000 200000 1000\n",
			hostID:  200005,
			wantID:  1005,
			wantOK:  true,
		},
		{
			name: "host id outside all ranges",
			content: "0 100000 65536\n",
			hostID:  999,
			wantID:  0,
			wantOK:  false,
		},
		{
			name:    "empty map",
			content: "",
			hostID:  0,
			wantID:  0,
			wantOK:  false,
		},
		{
			name: "malformed line is skipped",
			content: "not-a-number\n0 0 4294967295\n",
			hostID:  7,
			wantID:  7,
			wantOK:  true,
		},
		{
			name: "count zero boundary — exactly at end is excluded",
			content: "0 10 5\n", // covers host 10,11,12,13,14 → ns 0-4
			hostID:  15,         // one past the end
			wantID:  0,
			wantOK:  false,
		},
		{
			name: "count zero boundary — last valid entry",
			content: "0 10 5\n",
			hostID:  14, // ns 4
			wantID:  4,
			wantOK:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotID, gotOK := lookupIDInMap(tt.content, tt.hostID)
			assert.Equal(t, tt.wantOK, gotOK)
			if tt.wantOK {
				assert.Equal(t, tt.wantID, gotID)
			}
		})
	}
}

func TestParseTaskStat(t *testing.T) {
	tests := []struct {
		data   string
		fields []string
		err    error
	}{
		{
			data:   "1 (cmd) S 0 1 1 0 -1 4194560 30901 1011224 96 1826 185 2546 3273 2402 20 0 1 0 24 170409984 2900 18446744073709551615 1 1 0 0 0 0 671173123 4096 1260 0 0 0 17 7 0 0 12 0 0 0 0 0 0 0 0 0 0",
			fields: []string{"1", "cmd", "S", "0", "1", "1", "0", "-1", "4194560", "30901", "1011224", "96", "1826", "185", "2546", "3273", "2402", "20", "0", "1", "0", "24", "170409984", "2900", "18446744073709551615", "1", "1", "0", "0", "0", "0", "671173123", "4096", "1260", "0", "0", "0", "17", "7", "0", "0", "12", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
			err:    nil,
		},
		{
			data:   "1 (the cmd) S 0 1 1 0 -1 4194560 30901 1011224 96 1826 185 2546 3273 2402 20 0 1 0 24 170409984 2900 18446744073709551615 1 1 0 0 0 0 671173123 4096 1260 0 0 0 17 7 0 0 12 0 0 0 0 0 0 0 0 0 0",
			fields: []string{"1", "the cmd", "S", "0", "1", "1", "0", "-1", "4194560", "30901", "1011224", "96", "1826", "185", "2546", "3273", "2402", "20", "0", "1", "0", "24", "170409984", "2900", "18446744073709551615", "1", "1", "0", "0", "0", "0", "671173123", "4096", "1260", "0", "0", "0", "17", "7", "0", "0", "12", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
			err:    nil,
		},
		{
			data:   "1 cmd S 0 1 1 0 -1 4194560 30901 1011224 96 1826 185 2546 3273 2402 20 0 1 0 24 170409984 2900 18446744073709551615 1 1 0 0 0 0 671173123 4096 1260 0 0 0 17 7 0 0 12 0 0 0 0 0 0 0 0 0 0",
			fields: nil,
			err:    errors.New("task name is not parenthesized"),
		},
	}

	assert := assert.New(t)
	for _, tt := range tests {
		fields, err := parseTaskStat(tt.data)
		assert.Equal(fields, tt.fields)
		assert.Equal(err, tt.err)
	}
}

func TestProcessHasCapability(t *testing.T) {
	tests := []struct {
		name    string
		content string
		cap     uint
		want    bool
	}{
		{
			// Real value captured from a k3d+containerd gVisor cluster with
			// --host-uds=open configured: the gofer gains CAP_SETGID (bit 6)
			// and CAP_SETUID (bit 7) so it can forge SO_PEERCRED credentials.
			// Active caps: CHOWN, DAC_OVERRIDE, DAC_READ_SEARCH, FOWNER, FSETID,
			// SETGID, SETUID, SYS_CHROOT.
			name:    "CAP_SETUID present — real gVisor gofer with host-uds=open",
			content: "Name:\texe\nUid:\t0\t0\t0\t0\nCapEff:\t00000000000400df\n",
			cap:     capSetUID,
			want:    true,
		},
		{
			name:    "CAP_SETGID present — real gVisor gofer with host-uds=open",
			content: "Name:\texe\nUid:\t0\t0\t0\t0\nCapEff:\t00000000000400df\n",
			cap:     capSetGID,
			want:    true,
		},
		{
			// Real value captured from a gVisor gofer WITHOUT --host-uds configured.
			// Active caps: CHOWN, DAC_OVERRIDE, DAC_READ_SEARCH, FOWNER, FSETID,
			// SYS_CHROOT — NO SETUID, NO SETGID.
			name:    "CAP_SETUID absent — real gVisor gofer without host-uds",
			content: "Name:\texe\nUid:\t0\t0\t0\t0\nCapEff:\t000000000004001f\n",
			cap:     capSetUID,
			want:    false,
		},
		{
			name:    "CAP_SETUID absent — unprivileged process",
			content: "Name:\tmy-app\nCapEff:\t0000000000000000\n",
			cap:     capSetUID,
			want:    false,
		},
		{
			name:    "only CAP_SETUID bit set",
			content: "Name:\ttest\nCapEff:\t0000000000000080\n", // 1<<7
			cap:     capSetUID,
			want:    true,
		},
		{
			name:    "only CAP_SETGID bit set — CAP_SETUID absent",
			content: "Name:\ttest\nCapEff:\t0000000000000040\n", // 1<<6
			cap:     capSetUID,
			want:    false,
		},
		{
			name:    "CapEff line missing — returns false safely",
			content: "Name:\ttest\nUid:\t0 0 0 0\n",
			cap:     capSetUID,
			want:    false,
		},
		{
			name:    "malformed hex — returns false safely",
			content: "Name:\ttest\nCapEff:\tnot-hex\n",
			cap:     capSetUID,
			want:    false,
		},
		{
			name:    "empty status — returns false safely",
			content: "",
			cap:     capSetUID,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// processHasCapability reads from /proc/<pid>/status on disk;
			// test the underlying parsing logic directly via a helper that
			// accepts the file content as a string.
			got := parseCapEff(tt.content, tt.cap)
			assert.Equal(t, tt.want, got)
		})
	}
}

func newTestWatcher(uid, gid uint32) *linuxWatcher {
	log := logrus.New()
	log.SetOutput(io.Discard)
	return &linuxWatcher{
		uid: uid,
		gid: gid,
		log: log.WithField("test", true),
	}
}

func TestCheckUID(t *testing.T) {
	tests := []struct {
		name          string
		uid           uint32
		statUID       uint32
		uidMapContent string
		allowMismatch bool
		wantErr       bool
	}{
		{
			name:    "exact match — no error",
			uid:     1000,
			statUID: 1000,
			wantErr: false,
		},
		{
			name:          "uid_map remapping resolves mismatch",
			uid:           0,
			statUID:       100000,
			uidMapContent: "0 100000 65536\n",
			wantErr:       false,
		},
		{
			name:    "mismatch with allow_uid_mismatch false — error",
			uid:     0,
			statUID: 1000,
			wantErr: true,
		},
		{
			name:          "mismatch with allow_uid_mismatch true and CAP_SETUID — allowed",
			uid:           0,
			statUID:       1000,
			allowMismatch: true,
			wantErr:       false,
		},
		{
			name:          "mismatch with allow_uid_mismatch true but no CAP_SETUID — error",
			uid:           0,
			statUID:       1000,
			allowMismatch: false,
			wantErr:       true,
		},
		{
			name:          "uid_map does not cover statUID — falls through to allowMismatch check",
			uid:           0,
			statUID:       999,
			uidMapContent: "0 100000 65536\n",
			allowMismatch: false,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newTestWatcher(tt.uid, 0)
			err := w.checkUIDWith(tt.statUID, tt.uidMapContent, tt.allowMismatch)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "process uid")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCheckGID(t *testing.T) {
	tests := []struct {
		name          string
		gid           uint32
		statGID       uint32
		gidMapContent string
		allowMismatch bool
		wantErr       bool
	}{
		{
			name:    "exact match — no error",
			gid:     1000,
			statGID: 1000,
			wantErr: false,
		},
		{
			name:          "gid_map remapping resolves mismatch",
			gid:           0,
			statGID:       100000,
			gidMapContent: "0 100000 65536\n",
			wantErr:       false,
		},
		{
			name:    "mismatch with allow_uid_mismatch false — error",
			gid:     0,
			statGID: 1000,
			wantErr: true,
		},
		{
			name:          "mismatch with allow_uid_mismatch true and CAP_SETGID — allowed",
			gid:           0,
			statGID:       1000,
			allowMismatch: true,
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newTestWatcher(0, tt.gid)
			err := w.checkGIDWith(tt.statGID, tt.gidMapContent, tt.allowMismatch)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "process gid")
			} else {
				require.NoError(t, err)
			}
		})
	}
}
