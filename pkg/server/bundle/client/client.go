package client

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"

	spiffe_tls "github.com/spiffe/go-spiffe/tls"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/zeebo/errs"
)

type SPIFFEAuthConfig struct {
	// EndpointSpiffeID is the expected SPIFFE ID of the endpoint server. If unset, it
	// defaults to the SPIRE server ID within the trust domain.
	EndpointSpiffeID string

	// RootCAs is the set of root CA certificates used to authenticate the
	// endpoint server.
	RootCAs []*x509.Certificate
}

type ClientConfig struct { //nolint: golint // name stutter is intentional
	// TrustDomain is the federated trust domain (i.e. domain.test)
	TrustDomain string

	// EndpointAddress is the bundle endpoint for the trust domain.
	EndpointAddress string

	// SPIFFEAuth contains required configuration to authenticate the endpoint
	// using SPIFFE authentication. If unset, it is assumed that the endpoint
	// is authenticated via Web PKI.
	SPIFFEAuth *SPIFFEAuthConfig
}

// Client is used to fetch a bundle and metadata from a bundle endpoint
type Client interface {
	FetchBundle(context.Context) (*bundleutil.Bundle, error)
}

type client struct {
	c      ClientConfig
	client *http.Client
}

func NewClient(config ClientConfig) Client {
	httpClient := &http.Client{}
	if config.SPIFFEAuth != nil {
		spiffeID := config.SPIFFEAuth.EndpointSpiffeID
		if spiffeID == "" {
			spiffeID = idutil.ServerID(config.TrustDomain)
		}
		peer := &spiffe_tls.TLSPeer{
			SpiffeIDs:  []string{spiffeID},
			TrustRoots: util.NewCertPool(config.SPIFFEAuth.RootCAs...),
		}
		httpClient.Transport = &http.Transport{
			TLSClientConfig: peer.NewTLSConfig(nil),
		}
	}
	return &client{
		c:      config,
		client: httpClient,
	}
}

func (c *client) FetchBundle(ctx context.Context) (*bundleutil.Bundle, error) {
	resp, err := c.client.Get(fmt.Sprintf("https://%s", c.c.EndpointAddress))
	if err != nil {
		return nil, errs.New("failed to fetch bundle: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errs.New("unexpected status %d fetching bundle: %s", resp.StatusCode, tryRead(resp.Body))
	}

	b, err := bundleutil.Decode(idutil.TrustDomainID(c.c.TrustDomain), resp.Body)
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
