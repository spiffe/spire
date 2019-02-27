package k8s

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	rawSAT = "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJzcGlyZSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJzcGlyZS1hZ2VudC10b2tlbi16anI4diIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJzcGlyZS1hZ2VudCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjE4ODFlODRmLWI2MTItMTFlOC1hNTQzLTA4MDAyNzJjNmU0MiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpzcGlyZTpzcGlyZS1hZ2VudCJ9.MKhBSMEoYvsdnosPGLklNxDLZFbacO7iMQLNSmYn1YKnX2Dep6eeeIBNMqe4LfH1jD4gmy3Y053H4cyM-uW6NkwM-ER_CyQWtd3blD4pGqu4vKGc3QizeNjcBkp6dzz_M5lDHQ-oqntaY8vNpJ8mGS8eYOiTIr_Fl4OO_t4m1Pxt8ommixmTiFH6Gx9har15qIvWmMN4y7TRjqgD7Q6XXCIpXWo2xski1frhfh5adl0xCaW97qCctAfhnLeHB0Jcug-zbo-BIoYqixXiRvqB8l9M5H5xj6jd3QwOxhiO8Xd6ZqDe_xD1bSZCWqboGpO953-2OvBlGyS3IojUl8VMtQ"
)

func TestSATTokenClaims(t *testing.T) {
	token, err := jwt.ParseSigned(rawSAT)
	require.NoError(t, err)

	claims := new(SATClaims)
	err = token.UnsafeClaimsWithoutVerification(claims)
	require.NoError(t, err)

	require.Equal(t, "kubernetes/serviceaccount", claims.Issuer)
	require.Equal(t, "spire", claims.Namespace)
	require.Equal(t, "spire-agent", claims.ServiceAccountName)
}

func TestAgentID(t *testing.T) {
	require.Equal(t, "spiffe://example.org/spire/agent/k8s_sat/production/1234", AgentID("k8s_sat", "example.org", "production", "1234"))
}
