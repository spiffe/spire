package server

import "github.com/spiffe/spire/pkg/common/telemetry"

// StartNodeAPIAuthorizeCall return metric for
// the server's Node API, authorizing a call for the given method.
func StartNodeAPIAuthorizeCall(m telemetry.Metrics, method string) *telemetry.CallCounter {
	counter := telemetry.StartCall(m, telemetry.NodeAPI, telemetry.AuthorizeCall)
	counter.AddLabel(telemetry.Method, method)
	return counter
}

// StartNodeAPIAttestCall return metric for
// the server's Node API, Attestation of a node.
func StartNodeAPIAttestCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.NodeAPI, telemetry.Attest)
}

// StartNodeAPIFetchJWTSVIDCall return metric for
// the server's Node API, Fetch JWT SVID for node.
func StartNodeAPIFetchJWTSVIDCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.NodeAPI, telemetry.JWTSVID, telemetry.Fetch)
}

// StartNodeAPIFetchX509SVIDCall return metric for
// the server's Node API, Fetch X509 SVID for node.
func StartNodeAPIFetchX509SVIDCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.NodeAPI, telemetry.X509SVID, telemetry.Fetch)
}

// StartNodeAPIFetchX509CASVIDCall return metric for
// the server's Node API, Fetch X509 CA SVID for node.
func StartNodeAPIFetchX509CASVIDCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.NodeAPI, telemetry.X509CASVID, telemetry.Fetch)
}

// StartNodeAPIPushJWTKeyUpstreamCall return metric for
// the server's Node API, Push JWT Key Upstream.
func StartNodeAPIPushJWTKeyUpstreamCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.NodeAPI, telemetry.JWTKey, telemetry.Push)
}

// StartNodeAPIFetchBundleCall return metric for
// the server's Node API, Fetch the current bundle.
func StartNodeAPIFetchBundleCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.NodeAPI, telemetry.FetchBundle, telemetry.Fetch)
}

// End Call Counters
