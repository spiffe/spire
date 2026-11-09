package ca

import (
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

const (
	activationThresholdDivisor    = 6
	DefaultActivationThresholdCap = 7 * 24 * time.Hour
)

// WarnOnIncompatibleTTL warns when a requested TTL cannot be guaranteed by the
// configured authority rotation schedule. Unspecified TTLs use defaults, which
// are checked separately at startup.
func WarnOnIncompatibleTTL(log logrus.FieldLogger, caTTL, activationThresholdCap, ttl time.Duration, name string) {
	maxTTL := MaxSVIDTTLForCATTL(caTTL, activationThresholdCap)
	if ttl <= 0 || ttl <= maxTTL {
		return
	}
	log.WithFields(logrus.Fields{
		telemetry.Alert:        true,
		telemetry.AlertType:    telemetry.ShortenedLifetimeAlertType,
		telemetry.TTLName:      name,
		telemetry.RequestedTTL: ttl.Seconds(),
		telemetry.MaxTTL:       maxTTL.Seconds(),
		telemetry.CATTL:        caTTL.Seconds(),
	}).Warn("Requested TTL exceeds the lifetime guaranteed by scheduled authority rotation; shorter lifetimes may be issued")
}

// MaxSVIDTTL returns the maximum SVID lifetime that scheduled authority rotation
// can guarantee without shortening the issued lifetime.
func MaxSVIDTTL(activationThresholdCap time.Duration) time.Duration {
	return normalizedActivationThresholdCap(activationThresholdCap)
}

// MaxSVIDTTLForCATTL returns the maximum SVID lifetime guaranteed by scheduled
// rotation for the configured CA/signing key TTL.
func MaxSVIDTTLForCATTL(caTTL, activationThresholdCap time.Duration) time.Duration {
	return min(caTTL/activationThresholdDivisor, normalizedActivationThresholdCap(activationThresholdCap))
}

// MinCATTLForSVIDTTL returns the minimum CA/signing key TTL needed to accommodate
// the given SVID TTL. TTLs above MaxSVIDTTL cannot be guaranteed by rotation.
func MinCATTLForSVIDTTL(svidTTL time.Duration) time.Duration {
	return svidTTL * activationThresholdDivisor
}

func normalizedActivationThresholdCap(activationThresholdCap time.Duration) time.Duration {
	if activationThresholdCap == 0 {
		return DefaultActivationThresholdCap
	}
	return activationThresholdCap
}
