package jwtutil

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/zeebo/errs"
	"gopkg.in/square/go-jose.v2"
)

const (
	wellKnownOpenIDConfiguration = "/.well-known/openid-configuration"
)

type KeySetProvider interface {
	GetKeySet(context.Context) (*jose.JSONWebKeySet, error)
}

type KeySetProviderFunc func(context.Context) (*jose.JSONWebKeySet, error)

func (fn KeySetProviderFunc) GetKeySet(ctx context.Context) (*jose.JSONWebKeySet, error) {
	return fn(ctx)
}

type OIDCIssuer string

func (c OIDCIssuer) GetKeySet(ctx context.Context) (*jose.JSONWebKeySet, error) {
	u, err := url.Parse(string(c))
	if err != nil {
		return nil, errs.Wrap(err)
	}
	u.Path = path.Join(u.Path, wellKnownOpenIDConfiguration)

	uri, err := DiscoverKeySetURI(ctx, u.String())
	if err != nil {
		return nil, err
	}
	return FetchKeySet(ctx, uri)
}

type CachingKeySetProvider struct {
	provider        KeySetProvider
	refreshInterval time.Duration

	mu      sync.Mutex
	updated time.Time
	jwks    *jose.JSONWebKeySet

	hooks struct {
		now func() time.Time
	}
}

func NewCachingKeySetProvider(provider KeySetProvider, refreshInterval time.Duration) *CachingKeySetProvider {
	c := &CachingKeySetProvider{
		provider:        provider,
		refreshInterval: refreshInterval,
	}
	c.hooks.now = time.Now
	return c
}

func (c *CachingKeySetProvider) GetKeySet(ctx context.Context) (*jose.JSONWebKeySet, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.hooks.now()

	if !c.updated.IsZero() && now.Sub(c.updated) < c.refreshInterval {
		return c.jwks, nil
	}

	// refresh key set. if there is a failure, log and return the old set if
	// available.
	jwks, err := c.provider.GetKeySet(ctx)
	if err == nil {
		c.jwks = jwks
		c.updated = now
	} else {
		logrus.WithError(err).Warn("unable to refresh key set")
		if c.jwks == nil {
			return nil, errs.Wrap(err)
		}
	}

	return c.jwks, nil
}

func DiscoverKeySetURI(ctx context.Context, configURL string) (string, error) {
	req, err := http.NewRequest("GET", configURL, nil)
	if err != nil {
		return "", errs.Wrap(err)
	}
	req = req.WithContext(ctx)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", errs.Wrap(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errs.New("unexpected status code %d: %s", resp.StatusCode, tryRead(resp.Body))
	}

	config := &struct {
		JWKSURI string `json:"jwks_uri"`
	}{}
	if err := json.NewDecoder(resp.Body).Decode(config); err != nil {
		return "", errs.New("failed to decode configuration: %v", err)
	}
	if config.JWKSURI == "" {
		return "", errs.New("configuration missing JWKS URI")
	}

	return config.JWKSURI, nil
}

func FetchKeySet(ctx context.Context, jwksURI string) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequest("GET", jwksURI, nil)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	req = req.WithContext(ctx)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errs.New("unexpected status code %d: %s", resp.StatusCode, tryRead(resp.Body))
	}

	jwks := new(jose.JSONWebKeySet)
	if err := json.NewDecoder(resp.Body).Decode(jwks); err != nil {
		return nil, errs.New("failed to decode key set: %v", err)
	}

	return jwks, nil
}

func tryRead(r io.Reader) string {
	b := make([]byte, 1024)
	n, _ := r.Read(b)
	return string(b[:n])
}
