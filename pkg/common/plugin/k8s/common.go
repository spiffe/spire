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

// PSATClaims represents claims in a projected service account token, for example:
// {
// 	 "aud": [
// 	   "spire-server"
// 	 ],
// 	 "exp": 1550850854,
// 	 "iat": 1550843654,
// 	 "iss": "api",
// 	 "kubernetes.io": {
// 	   "namespace": "spire",
// 	   "pod": {
// 	 	"name": "spire-agent-5d84p",
// 	 	"uid": "56857f33-36a9-11e9-860c-080027b25557"
// 	   },
// 	   "serviceaccount": {
// 	 	"name": "spire-agent",
// 	 	"uid": "ca29bd95-36a8-11e9-b8af-080027b25557"
// 	   }
// 	 },
// 	 "nbf": 1550843654,
// 	 "sub": "system:serviceaccount:spire:spire-agent"
// }
type PSATClaims struct {
	jwt.Claims
	K8s struct {
		Namespace string `json:"namespace"`

		Pod struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"pod"`

		ServiceAccount struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"serviceaccount"`
	} `json:"kubernetes.io"`
}

type SATAttestationData struct {
	Cluster string `json:"cluster"`
	UUID    string `json:"uuid"`
	Token   string `json:"token"`
}

func AgentID(tokenType, trustDomain, cluster, uuid string) string {
	u := url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   path.Join("spire", "agent", tokenType, cluster, uuid),
	}
	return u.String()
}
