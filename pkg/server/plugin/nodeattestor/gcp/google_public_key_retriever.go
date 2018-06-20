package gcp

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type googlePublicKeyRetriever struct {
	url    string
	expiry time.Time

	mtx          sync.Mutex
	certificates map[string]*x509.Certificate
}

func (r *googlePublicKeyRetriever) retrieveKey(token *jwt.Token) (interface{}, error) {
	if token.Header["kid"] == nil {
		return nil, errors.New("token is missing kid value")
	}
	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, errors.New("token has unexpected kid value")
	}
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %T", token.Method)
	}

	r.mtx.Lock()
	defer r.mtx.Unlock()

	if r.expiry.IsZero() || time.Now().After(r.expiry) {
		err := r.downloadCertificates()
		if err != nil {
			return nil, err
		}
	}
	cert, ok := r.certificates[kid]
	if !ok {
		return nil, errors.New("no certificate found for kid")
	}
	return cert.PublicKey, nil
}

func (r *googlePublicKeyRetriever) downloadCertificates() error {
	resp, err := http.Get(r.url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var data map[string]string
	if err := json.Unmarshal(bytes, &data); err != nil {
		return fmt.Errorf("unable to unmarshal certificate response: %v", err)
	}

	certificates := make(map[string]*x509.Certificate)
	for k, v := range data {
		block, _ := pem.Decode([]byte(v))
		if block == nil {
			return errors.New("unable to unmarshal certificate response: malformed PEM block")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("unable to unmarshal certificate response: malformed certificate PEM")
		}
		certificates[k] = cert
	}

	r.expiry = time.Time{}
	if expires := resp.Header.Get("Expires"); expires != "" {
		if t, err := time.Parse("Mon, 2 Jan 2006 15:04:05 MST", expires); err == nil {
			r.expiry = t
		}
	}
	r.certificates = certificates
	return nil
}
