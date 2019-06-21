package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	testServerLine = `time="2019-04-22T23:04:07Z" level=debug msg="Signed X509 SVID" expires_at="2019-04-23T00:04:07Z" is_ca=false spiffe_id="spiffe://example.org/spire/server" subsystem_name=ca`
	testAgentLine  = `time="2019-04-22T23:04:07Z" level=debug msg="Signed X509 SVID" expires_at="2019-04-23T00:04:07Z" is_ca=false spiffe_id="spiffe://example.org/spire/agent/k8s_psat/example-cluster/minikube" subsystem_name=ca`
)

func TestParseAttestedNodeID(t *testing.T) {
	nodeID, ok := parseAttestedNodeID(testServerLine)
	require.False(t, ok)
	require.Empty(t, nodeID)

	nodeID, ok = parseAttestedNodeID(testAgentLine)
	require.True(t, ok)
	require.Equal(t, "spiffe://example.org/spire/agent/k8s_psat/example-cluster/minikube", nodeID)
}
