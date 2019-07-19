package k8s

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/spiffe/spire/proto/spire/common"
	"gopkg.in/square/go-jose.v2/jwt"
	authv1 "k8s.io/api/authentication/v1"
)

const (
	k8sPodNameKey = "authentication.kubernetes.io/pod-name"
	k8sPodUIDKey  = "authentication.kubernetes.io/pod-uid"
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
	Token   string `json:"token"`
}

type PSATAttestationData struct {
	Cluster string `json:"cluster"`
	Token   string `json:"token"`
}

func AgentID(pluginName, trustDomain, cluster, uuid string) string {
	u := url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   path.Join("spire", "agent", pluginName, cluster, uuid),
	}
	return u.String()
}

func MakeSelector(pluginName, kind, value string) *common.Selector {
	return &common.Selector{
		Type:  pluginName,
		Value: fmt.Sprintf("%s:%s", kind, value),
	}
}

// GetNamesFromTokenStatus parses a fully qualified k8s username like: 'system:serviceaccount:spire:spire-agent'
// from tokenStatus. The string is split and the last two names are returned: namespace and service account name
func GetNamesFromTokenStatus(tokenStatus *authv1.TokenReviewStatus) (string, string, error) {
	username := tokenStatus.User.Username
	if username == "" {
		return "", "", errors.New("empty username")
	}

	names := strings.Split(username, ":")
	if len(names) != 4 {
		return "", "", fmt.Errorf("unexpected username format: %v", username)
	}

	if names[2] == "" {
		return "", "", fmt.Errorf("missing namespace")
	}

	if names[3] == "" {
		return "", "", fmt.Errorf("missing service account name")
	}

	return names[2], names[3], nil
}

// GetPodNameFromTokenStatus extracts pod name from a tokenReviewStatus type
func GetPodNameFromTokenStatus(tokenStatus *authv1.TokenReviewStatus) (string, error) {
	podName, ok := tokenStatus.User.Extra[k8sPodNameKey]
	if !ok {
		return "", errors.New("missing pod name")
	}

	if len(podName) != 1 {
		return "", fmt.Errorf("expected 1 name but got: %d", len(podName))
	}

	if podName[0] == "" {
		return "", errors.New("pod name is empty")
	}

	return podName[0], nil
}

// GetPodUIDFromTokenStatus extracts pod UID from a tokenReviewStatus type
func GetPodUIDFromTokenStatus(tokenStatus *authv1.TokenReviewStatus) (string, error) {
	podUID, ok := tokenStatus.User.Extra[k8sPodUIDKey]
	if !ok {
		return "", errors.New("missing pod UID")
	}

	if len(podUID) != 1 {
		return "", fmt.Errorf("expected 1 UID but got: %d", len(podUID))
	}

	if podUID[0] == "" {
		return "", errors.New("pod UID is empty")
	}

	return podUID[0], nil
}
