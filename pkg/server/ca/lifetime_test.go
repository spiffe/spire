package ca

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/stretchr/testify/require"
)

func TestWarnOnIncompatibleTTL(t *testing.T) {
	for _, tt := range []struct {
		name  string
		caTTL time.Duration
		ttl   time.Duration
		warn  bool
	}{
		{name: "default", caTTL: time.Hour, ttl: 0},
		{name: "below boundary", caTTL: time.Hour, ttl: 9 * time.Minute},
		{name: "at boundary", caTTL: time.Hour, ttl: 10 * time.Minute},
		{name: "above boundary", caTTL: time.Hour, ttl: 10*time.Minute + time.Second, warn: true},
		{name: "at seven day cap", caTTL: 90 * 24 * time.Hour, ttl: 7 * 24 * time.Hour},
		{name: "above seven day cap", caTTL: 90 * 24 * time.Hour, ttl: 8 * 24 * time.Hour, warn: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			log, hook := test.NewNullLogger()
			WarnOnIncompatibleTTL(log, tt.caTTL, tt.ttl, "x509_svid_ttl")
			if !tt.warn {
				require.Empty(t, hook.AllEntries())
				return
			}
			require.Len(t, hook.AllEntries(), 1)
			entry := hook.LastEntry()
			require.Equal(t, logrus.WarnLevel, entry.Level)
			require.Equal(t, logrus.Fields{
				telemetry.Alert:        true,
				telemetry.AlertType:    telemetry.ShortenedLifetimeAlertType,
				telemetry.TTLName:      "x509_svid_ttl",
				telemetry.RequestedTTL: tt.ttl.Seconds(),
				telemetry.MaxTTL:       MaxSVIDTTLForCATTL(tt.caTTL).Seconds(),
				telemetry.CATTL:        tt.caTTL.Seconds(),
			}, entry.Data)
		})
	}
}
