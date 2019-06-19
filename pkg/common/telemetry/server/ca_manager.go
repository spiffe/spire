package server

import "github.com/spiffe/spire/pkg/common/telemetry"

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartCAManagerPruneBundleCall returns metric for
// for server CA manager bundle pruning
func StartCAManagerPruneBundleCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.CA, telemetry.Manager, telemetry.Bundle, telemetry.Prune)
}

// StartServerCAManagerPrepareJWTKeyCall return metric for
// Server CA Manager preparing a JWT Key
func StartServerCAManagerPrepareJWTKeyCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.CA, telemetry.Manager, telemetry.JWTKey, telemetry.Prepare)
}

// StartServerCAManagerPrepareX509CACall return metric for
// Server CA Manager preparing an X509 CA
func StartServerCAManagerPrepareX509CACall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.CA, telemetry.Manager, telemetry.X509CA, telemetry.Prepare)
}

// End Call Counters

// Gauge (remember previous value set)

// SetX509CARotateGauge set gauge for X509 CA rotation,
// TTL of CA for a specific TrustDomain
func SetX509CARotateGauge(m telemetry.Metrics, trustDomain string, val float32) {
	m.SetGaugeWithLabels(
		[]string{telemetry.Manager, telemetry.X509CA, telemetry.Rotate, telemetry.TTL},
		val,
		[]telemetry.Label{
			{Name: telemetry.TrustDomainID, Value: trustDomain},
		})
}

// End Gauge

// Counters (literal increments, not call counters)

// IncrActivateJWTKeyManagerCounter indicate activation
// of JWT Key manager
func IncrActivateJWTKeyManagerCounter(m telemetry.Metrics) {
	m.IncrCounter([]string{telemetry.Manager, telemetry.JWTKey, telemetry.Activate}, 1)
}

// IncrActivateX509CAManagerCounter indicate activation
// of X509 CA manager
func IncrActivateX509CAManagerCounter(m telemetry.Metrics) {
	m.IncrCounter([]string{telemetry.CA, telemetry.Manager, telemetry.X509CA, telemetry.Activate}, 1)
}

// IncrManagerPrunedBundleCounter indicate manager
// having pruned a bundle
func IncrManagerPrunedBundleCounter(m telemetry.Metrics) {
	m.IncrCounter([]string{telemetry.CA, telemetry.Manager, telemetry.Bundle, telemetry.Pruned}, 1)
}

// IncrServerCASignJWTSVIDCounter indicate Server CA
// signed a JWT SVID. Takes SVID's SPIFFE ID and audience(s)
func IncrServerCASignJWTSVIDCounter(m telemetry.Metrics, id string, auds ...string) {
	labels := []telemetry.Label{
		{
			Name:  telemetry.SPIFFEID,
			Value: id,
		},
	}
	for _, audience := range auds {
		labels = append(labels, telemetry.Label{
			Name:  telemetry.Audience,
			Value: audience,
		})
	}
	m.IncrCounterWithLabels([]string{telemetry.ServerCA, telemetry.Sign, telemetry.JWTSVID}, 1, labels)
}

// IncrServerCASignX509CACounter indicate Server CA
// signed an X509 CA SVID. Takes SVID's SPIFFE ID
func IncrServerCASignX509CACounter(m telemetry.Metrics, id string) {
	m.IncrCounterWithLabels([]string{telemetry.ServerCA, telemetry.Sign, telemetry.X509CASVID}, 1, []telemetry.Label{
		{
			Name:  telemetry.SPIFFEID,
			Value: id,
		},
	})
}

// IncrServerCASignX509Counter indicate Server CA
// signed an X509 SVID. Takes SVID's SPIFFE ID
func IncrServerCASignX509Counter(m telemetry.Metrics, id string) {
	m.IncrCounterWithLabels([]string{telemetry.ServerCA, telemetry.Sign, telemetry.X509SVID}, 1, []telemetry.Label{
		{
			Name:  telemetry.SPIFFEID,
			Value: id,
		},
	})
}

// End Counters
