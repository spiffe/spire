package k8s

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	rawSAT  = "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJzcGlyZSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJzcGlyZS1hZ2VudC10b2tlbi16anI4diIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJzcGlyZS1hZ2VudCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjE4ODFlODRmLWI2MTItMTFlOC1hNTQzLTA4MDAyNzJjNmU0MiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpzcGlyZTpzcGlyZS1hZ2VudCJ9.MKhBSMEoYvsdnosPGLklNxDLZFbacO7iMQLNSmYn1YKnX2Dep6eeeIBNMqe4LfH1jD4gmy3Y053H4cyM-uW6NkwM-ER_CyQWtd3blD4pGqu4vKGc3QizeNjcBkp6dzz_M5lDHQ-oqntaY8vNpJ8mGS8eYOiTIr_Fl4OO_t4m1Pxt8ommixmTiFH6Gx9har15qIvWmMN4y7TRjqgD7Q6XXCIpXWo2xski1frhfh5adl0xCaW97qCctAfhnLeHB0Jcug-zbo-BIoYqixXiRvqB8l9M5H5xj6jd3QwOxhiO8Xd6ZqDe_xD1bSZCWqboGpO953-2OvBlGyS3IojUl8VMtQ"
	rawPSAT = "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJhdWQiOlsic3BpcmUtc2VydmVyIl0sImV4cCI6MTU1MTMwNzk0MCwiaWF0IjoxNTUxMzAwNzQwLCJpc3MiOiJhcGkiLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6InNwaXJlIiwicG9kIjp7Im5hbWUiOiJzcGlyZS1hZ2VudC1qY2RncCIsInVpZCI6IjkzNDQwOWMyLTNhZDEtMTFlOS1hOTU2LTA4MDAyNzI1OTE3NSJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoic3BpcmUtYWdlbnQiLCJ1aWQiOiI5MmYzOGU4My0zYWQxLTExZTktYTk1Ni0wODAwMjcyNTkxNzUifX0sIm5iZiI6MTU1MTMwMDc0MCwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OnNwaXJlOnNwaXJlLWFnZW50In0.KSNfey5GKFJoI94KruLzfZKfRlSu66gWK-Ks9Wx_KIBA2cWG_hmSYvmx_19BPzFe_YFEpTkdfnAmRPzC7f14SKmFqaewfQyoI7oiuqstHkOk-Qhc3Er42XQdCTPNvQ--ZbKZE0zgjFyuAySiQe2yeHxBoXnf6Nd29PFrvI6qvoJVEvqdrhcd0sl0qptFOoXfxOOc6mEdFLRmUqh1t3BRVFiULDVaKl_15LELdSUonf38O88y5_7xl0sOtv_TF2fxFucGssUVww794djSy-u3DCfDx4m6GsDJFfdsMbpUGhlg0j9TpVkv7xmI-ZumE-CNll-LNxyn9vlEomnxUZRZzg"
)

func TestSATClaims(t *testing.T) {
	token, err := jwt.ParseSigned(rawSAT)
	require.NoError(t, err)

	claims := new(SATClaims)
	err = token.UnsafeClaimsWithoutVerification(claims)
	require.NoError(t, err)

	require.Equal(t, "kubernetes/serviceaccount", claims.Issuer)
	require.Equal(t, "spire", claims.Namespace)
	require.Equal(t, "spire-agent", claims.ServiceAccountName)
}

func TestPSATClaims(t *testing.T) {
	token, err := jwt.ParseSigned(rawPSAT)
	require.NoError(t, err)

	claims := new(PSATClaims)
	err = token.UnsafeClaimsWithoutVerification(claims)
	require.NoError(t, err)

	require.Equal(t, "api", claims.Issuer)
	require.Equal(t, "spire", claims.K8s.Namespace)
	require.Equal(t, "spire-agent", claims.K8s.ServiceAccount.Name)
	require.Equal(t, "spire-agent-jcdgp", claims.K8s.Pod.Name)
}
func TestAgentID(t *testing.T) {
	require.Equal(t, "spiffe://example.org/spire/agent/k8s_sat/production/1234", AgentID("k8s_sat", "example.org", "production", "1234"))
}
