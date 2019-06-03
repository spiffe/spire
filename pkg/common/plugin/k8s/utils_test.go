package k8s

import (
	"testing"

	"github.com/stretchr/testify/assert"
	authv1 "k8s.io/api/authentication/v1"

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

func TestMakeSelector(t *testing.T) {
	s := MakeSelector("k8s_sat", "agent_ns", "spire")
	assert.Equal(t, "k8s_sat", s.Type)
	assert.Equal(t, "agent_ns:spire", s.Value)
}

func TestGetNamesFromTokenStatusFailIfUsernameIsEmpty(t *testing.T) {
	status := createTokenStatusWithUsername("")
	namespace, serviceAccount, err := GetNamesFromTokenStatus(status)
	assert.Empty(t, namespace)
	assert.Empty(t, serviceAccount)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty username")
}
func TestGetNamesFromTokenStatusFailIfUsernameHasWrongFormat(t *testing.T) {
	status := createTokenStatusWithUsername("not expected username format")
	namespace, serviceAccount, err := GetNamesFromTokenStatus(status)
	assert.Empty(t, namespace)
	assert.Empty(t, serviceAccount)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected username format")
}

func TestGetNamesFromTokenStatusFailIfMissingNamespace(t *testing.T) {
	status := createTokenStatusWithUsername("system:serviceaccount::SERVICE-ACCOUNT-NAME")
	namespace, serviceAccount, err := GetNamesFromTokenStatus(status)
	assert.Empty(t, namespace)
	assert.Empty(t, serviceAccount)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing namespace")
}

func TestGetNamesFromTokenStatusFailIfMissingAccountName(t *testing.T) {
	status := createTokenStatusWithUsername("system:serviceaccount:NAMESPACE:")
	namespace, serviceAccount, err := GetNamesFromTokenStatus(status)
	assert.Empty(t, namespace)
	assert.Empty(t, serviceAccount)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing service account name")
}

func TestGetNamesFromTokenStatusSucceeds(t *testing.T) {
	status := createTokenStatusWithUsername("system:serviceaccount:NAMESPACE:SERVICE-ACCOUNT-NAME")
	namespace, serviceAccount, err := GetNamesFromTokenStatus(status)
	assert.Equal(t, "NAMESPACE", namespace)
	assert.Equal(t, "SERVICE-ACCOUNT-NAME", serviceAccount)
	assert.NoError(t, err)
}

func TestGetPodNameFromTokenStatusFailsIfMissingPodNameValue(t *testing.T) {
	values := make(map[string]authv1.ExtraValue)
	status := createTokenStatusWithExtraValues(values)

	podName, err := GetPodNameFromTokenStatus(status)
	assert.Empty(t, podName)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing pod name")
}

func TestGetPodNameFromTokenStatusFailsIfMoreThanOnePodNameExists(t *testing.T) {
	values := make(map[string]authv1.ExtraValue)
	values[k8sPodNameKey] = authv1.ExtraValue([]string{"POD-NAME-1", "POD-NAME-2"})
	status := createTokenStatusWithExtraValues(values)

	podName, err := GetPodNameFromTokenStatus(status)
	assert.Empty(t, podName)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected 1 name but got: 2")
}

func TestGetPodNameFromTokenStatusFailsIfPodNameIsEmpty(t *testing.T) {
	values := make(map[string]authv1.ExtraValue)
	values[k8sPodNameKey] = authv1.ExtraValue([]string{""})
	status := createTokenStatusWithExtraValues(values)

	podName, err := GetPodNameFromTokenStatus(status)
	assert.Empty(t, podName)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "pod name is empty")
}

func TestGetPodNameFromTokenStatusSucceeds(t *testing.T) {
	values := make(map[string]authv1.ExtraValue)
	values[k8sPodNameKey] = authv1.ExtraValue([]string{"POD-NAME"})
	status := createTokenStatusWithExtraValues(values)

	podName, err := GetPodNameFromTokenStatus(status)
	assert.Equal(t, "POD-NAME", podName)
	assert.NoError(t, err)
}

func TestGetPodUIDFromTokenStatusFailsIfMissingPodUIDValue(t *testing.T) {
	values := make(map[string]authv1.ExtraValue)
	status := createTokenStatusWithExtraValues(values)

	podUID, err := GetPodUIDFromTokenStatus(status)
	assert.Empty(t, podUID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing pod UID")
}

func TestGetPodUIDFromTokenStatusFailsIfMoreThanOnePodUIDExists(t *testing.T) {
	values := make(map[string]authv1.ExtraValue)
	values[k8sPodUIDKey] = authv1.ExtraValue([]string{"POD-UID-1", "POD-UID-2"})
	status := createTokenStatusWithExtraValues(values)

	podUID, err := GetPodUIDFromTokenStatus(status)
	assert.Empty(t, podUID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected 1 UID but got: 2")
}

func TestGetPodUIDFromTokenStatusFailsIfPodUIDIsEmpty(t *testing.T) {
	values := make(map[string]authv1.ExtraValue)
	values[k8sPodUIDKey] = authv1.ExtraValue([]string{""})
	status := createTokenStatusWithExtraValues(values)

	podUID, err := GetPodUIDFromTokenStatus(status)
	assert.Empty(t, podUID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "pod UID is empty")
}

func TestGetPodUIDFromTokenStatusSucceeds(t *testing.T) {
	values := make(map[string]authv1.ExtraValue)
	values[k8sPodUIDKey] = authv1.ExtraValue([]string{"POD-UID"})
	status := createTokenStatusWithExtraValues(values)

	podUID, err := GetPodUIDFromTokenStatus(status)
	assert.Equal(t, "POD-UID", podUID)
	assert.NoError(t, err)
}

func createTokenStatusWithUsername(username string) *authv1.TokenReviewStatus {
	return &authv1.TokenReviewStatus{
		User: authv1.UserInfo{
			Username: username,
		},
	}
}

func createTokenStatusWithExtraValues(values map[string]authv1.ExtraValue) *authv1.TokenReviewStatus {
	return &authv1.TokenReviewStatus{
		User: authv1.UserInfo{
			Extra: values,
		},
	}
}
