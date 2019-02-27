package k8s

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"path"

	"github.com/spiffe/spire/proto/common"
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

func VerifyTokenSignature(keys []crypto.PublicKey, token *jwt.JSONWebToken, claims interface{}) (err error) {
	var lastErr error
	for _, key := range keys {
		if err := token.Claims(key, claims); err != nil {
			lastErr = fmt.Errorf("unable to verify token: %v", err)
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("token signed by unknown authority")
	}
	return lastErr
}

func LoadServiceAccountKeys(path string) ([]crypto.PublicKey, error) {
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var keys []crypto.PublicKey
	for {
		var pemBlock *pem.Block
		pemBlock, pemBytes = pem.Decode(pemBytes)
		if pemBlock == nil {
			return keys, nil
		}
		key, err := decodeKeyBlock(pemBlock)
		if err != nil {
			return nil, err
		}
		if key != nil {
			keys = append(keys, key)
		}
	}
}

func MakeSelector(pluginName, kind, value string) *common.Selector {
	return &common.Selector{
		Type:  pluginName,
		Value: fmt.Sprintf("%s:%s", kind, value),
	}
}

func decodeKeyBlock(block *pem.Block) (crypto.PublicKey, error) {
	var key crypto.PublicKey
	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = cert.PublicKey
	case "RSA PUBLIC KEY":
		rsaKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = rsaKey
	case "PUBLIC KEY":
		pkixKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = pkixKey
	default:
		return nil, nil
	}

	if !isSupportedKey(key) {
		return nil, fmt.Errorf("unsupported %T in %s block", key, block.Type)
	}
	return key, nil
}

func isSupportedKey(key crypto.PublicKey) bool {
	switch key.(type) {
	case *rsa.PublicKey:
		return true
	case *ecdsa.PublicKey:
		return true
	default:
		return false
	}
}
