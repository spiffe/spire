package gcp

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type googlePublicKeyRetriever struct {
	certificates map[string]*x509.Certificate
	expirey      int64
	mtx          *sync.Mutex
}

func (r *googlePublicKeyRetriever) retrieveKey(token *jwt.Token) (interface{}, error) {
	if token.Header["kid"] == nil {
		return nil, fmt.Errorf("Missing kid in identityToken header. Cannot verify token")
	}
	kid := token.Header["kid"].(string)
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
	}

	if r.expirey == 0 || time.Now().Unix() > r.expirey {
		r.mtx.Lock()
		defer r.mtx.Unlock()
		err := r.downloadCertificates()
		if err != nil {
			return nil, err
		}
	}
	return r.certificates[kid].PublicKey, nil
}

func (r *googlePublicKeyRetriever) downloadCertificates() error {
	resp, err := http.Get(googleCertURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var data map[string]string
	err = json.Unmarshal(bytes, &data)

	for k, v := range data {
		block, _ := pem.Decode([]byte(v))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		r.certificates[k] = cert
	}
	t, err := time.Parse("Mon, 2 Jan 2006 15:04:05 MST", resp.Header["Expires"][0])
	r.expirey = t.Unix()
	return nil
}
