package k8s

import (
	"net/url"
	"path"

	"gopkg.in/square/go-jose.v2/jwt"
)

// SATClaims represents claims in a service account token, for example:
// {
//   "iss": "kubernetes/serviceaccount",
//   "kubernetes.io/serviceaccount/namespace": "spire",
//   "kubernetes.io/serviceaccount/secret.name": "spire-agent-token-zjr8v",
//   "kubernetes.io/serviceaccount/service-account.name": "spire-agent",
//   "kubernetes.io/serviceaccount/service-account.uid": "1881e84f-b612-11e8-a543-0800272c6e42",
//   "sub": "system:serviceaccount:spire:spire-agent"
// }
type SATClaims struct {
	jwt.Claims
	Namespace          string `json:"kubernetes.io/serviceaccount/namespace"`
	ServiceAccountName string `json:"kubernetes.io/serviceaccount/service-account.name"`
}

type SATAttestationData struct {
	UUID  string `json:"uuid"`
	Token string `json:"token"`
}

func AgentID(trustDomain, podUID string) string {
	u := url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   path.Join("spire", "agent", "k8s_sat", podUID),
	}
	return u.String()
}
