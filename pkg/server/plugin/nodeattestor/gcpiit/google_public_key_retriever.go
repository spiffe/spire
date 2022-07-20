package gcpiit

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"gopkg.in/square/go-jose.v2"
)

type googlePublicKeyRetriever struct {
	url    string
	expiry time.Time

	mtx  sync.Mutex
	jwks *jose.JSONWebKeySet
}

func newGooglePublicKeyRetriever(url string) *googlePublicKeyRetriever {
	return &googlePublicKeyRetriever{
		url:  url,
		jwks: &jose.JSONWebKeySet{},
	}
}

func (r *googlePublicKeyRetriever) retrieveJWKS(ctx context.Context) (*jose.JSONWebKeySet, error) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	if r.expiry.IsZero() || time.Now().After(r.expiry) {
		if err := r.downloadJWKS(ctx); err != nil {
			return nil, err
		}
	}
	return r.jwks, nil
}

func (r *googlePublicKeyRetriever) downloadJWKS(ctx context.Context) error {
	req, err := http.NewRequest("GET", r.url, nil)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var data map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return fmt.Errorf("unable to unmarshal certificate response: %w", err)
	}

	jwks := new(jose.JSONWebKeySet)
	for k, v := range data {
		block, _ := pem.Decode([]byte(v))
		if block == nil {
			return errors.New("unable to unmarshal certificate response: malformed PEM block")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("unable to unmarshal certificate response: malformed certificate PEM")
		}
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			KeyID:        k,
			Key:          cert.PublicKey,
			Certificates: []*x509.Certificate{cert},
		})
	}

	r.expiry = time.Time{}
	if expires := resp.Header.Get("Expires"); expires != "" {
		if t, err := time.Parse("Mon, 2 Jan 2006 15:04:05 MST", expires); err == nil {
			r.expiry = t
		}
	}
	r.jwks = jwks
	return nil
}
