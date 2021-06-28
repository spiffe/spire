package client

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/zeebo/errs"
)

type SPIFFEAuthConfig struct {
	// EndpointSpiffeID is the expected SPIFFE ID of the bundle endpoint server.
	EndpointSpiffeID spiffeid.ID

	// RootCAs is the set of root CA certificates used to authenticate the
	// endpoint server.
	RootCAs []*x509.Certificate
}

type ClientConfig struct { //nolint: golint // name stutter is intentional
	// TrustDomain is the federated trust domain (i.e. domain.test)
	TrustDomain spiffeid.TrustDomain

	// EndpointURL is the URL used to fetch the bundle of the federated
	// trust domain. Is served by a SPIFFE bundle endpoint server.
	EndpointURL string

	// SPIFFEAuth contains required configuration to authenticate the endpoint
	// using SPIFFE authentication. If unset, it is assumed that the endpoint
	// is authenticated via Web PKI.
	SPIFFEAuth *SPIFFEAuthConfig

	// DeprecatedConfig indicates that the configuration comes from a deprecated
	// configuration.
	// TODO: Remove support for this deprecated config in 1.1.0.
	DeprecatedConfig bool
}

// Client is used to fetch a bundle and metadata from a bundle endpoint
type Client interface {
	FetchBundle(context.Context) (*bundleutil.Bundle, error)
}

type client struct {
	c      ClientConfig
	client *http.Client
}

func NewClient(config ClientConfig) (Client, error) {
	httpClient := &http.Client{}
	if config.SPIFFEAuth != nil {
		endpointID := config.SPIFFEAuth.EndpointSpiffeID
		if endpointID.IsZero() {
			if config.DeprecatedConfig {
				// This is to preserve behavioral compatibility when using
				// the deprecated config and will be removed in 1.1.0.
				endpointID = idutil.ServerID(config.TrustDomain)
			} else {
				return nil, fmt.Errorf("no SPIFFE ID specified for federation with %q", config.TrustDomain.String())
			}
		}

		bundle := x509bundle.FromX509Authorities(endpointID.TrustDomain(), config.SPIFFEAuth.RootCAs)

		authorizer := tlsconfig.AuthorizeID(endpointID)

		httpClient.Transport = &http.Transport{
			TLSClientConfig: tlsconfig.TLSClientConfig(bundle, authorizer),
		}
	}
	return &client{
		c:      config,
		client: httpClient,
	}, nil
}

func (c *client) FetchBundle(ctx context.Context) (*bundleutil.Bundle, error) {
	resp, err := c.client.Get(c.c.EndpointURL)
	if err != nil {
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
