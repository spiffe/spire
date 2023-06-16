package client

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/zeebo/errs"
)

type SPIFFEAuthConfig struct {
	// EndpointSpiffeID is the expected SPIFFE ID of the bundle endpoint server.
	EndpointSpiffeID spiffeid.ID

	// RootCAs is the set of root CA certificates used to authenticate the
	// endpoint server.
	RootCAs []*x509.Certificate
}

type ClientConfig struct { //revive:disable-line:exported name stutter is intentional
	// TrustDomain is the federated trust domain (i.e. domain.test)
	TrustDomain spiffeid.TrustDomain

	// EndpointURL is the URL used to fetch the bundle of the federated
	// trust domain. Is served by a SPIFFE bundle endpoint server.
	EndpointURL string

	// SPIFFEAuth contains required configuration to authenticate the endpoint
	// using SPIFFE authentication. If unset, it is assumed that the endpoint
	// is authenticated via Web PKI.
	SPIFFEAuth *SPIFFEAuthConfig

	// mutateTransportHook is a hook to influence the transport used during
	// tests.
	mutateTransportHook func(*http.Transport)
}

// Client is used to fetch a bundle and metadata from a bundle endpoint
type Client interface {
	FetchBundle(context.Context) (*spiffebundle.Bundle, error)
}

type client struct {
	c      ClientConfig
	client *http.Client
}

func NewClient(config ClientConfig) (Client, error) {
	transport := newTransport()
	if config.SPIFFEAuth != nil {
		endpointID := config.SPIFFEAuth.EndpointSpiffeID
		if endpointID.IsZero() {
			return nil, fmt.Errorf("no SPIFFE ID specified for federation with %q", config.TrustDomain.Name())
		}

		bundle := x509bundle.FromX509Authorities(endpointID.TrustDomain(), config.SPIFFEAuth.RootCAs)

		authorizer := tlsconfig.AuthorizeID(endpointID)

		transport.TLSClientConfig = tlsconfig.TLSClientConfig(bundle, authorizer)
	}
	if config.mutateTransportHook != nil {
		config.mutateTransportHook(transport)
	}
	return &client{
		c:      config,
		client: &http.Client{Transport: transport},
	}, nil
}

func (c *client) FetchBundle(context.Context) (*spiffebundle.Bundle, error) {
	resp, err := c.client.Get(c.c.EndpointURL)
	if err != nil {
		var hostnameError x509.HostnameError
		if errors.As(err, &hostnameError) && c.c.SPIFFEAuth == nil && len(hostnameError.Certificate.URIs) > 0 {
			if id, idErr := spiffeid.FromString(hostnameError.Certificate.URIs[0].String()); idErr == nil {
				return nil, errs.New("failed to authenticate bundle endpoint using web authentication but the server certificate contains SPIFFE ID %q: maybe use https_spiffe instead of https_web: %v", id, err)
			}
		}
		return nil, errs.New("failed to fetch bundle: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errs.New("unexpected status %d fetching bundle: %s", resp.StatusCode, tryRead(resp.Body))
	}

	b, err := bundleutil.Decode(c.c.TrustDomain, resp.Body)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func tryRead(r io.Reader) string {
	b := make([]byte, 1024)
	n, _ := r.Read(b)
	return string(b[:n])
}

func newTransport() *http.Transport {
	return http.DefaultTransport.(*http.Transport).Clone()
}
