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
	"github.com/spiffe/spire/pkg/server/bundle"
	"github.com/zeebo/errs"
)

type ClientConfig struct {
	// TrustDomain is the federated trust domain (i.e. domain.test)
	TrustDomain string

	// EndpointAddress is the bundle endpoint for the trust domain.
	EndpointAddress string

	// EndpointSpiffeID is the expected SPIFFE ID of the endpoint server. If unset, it
	// defaults to the SPIRE server ID within the trust domain.
	EndpointSpiffeID string

	// RootCAs is the set of root CA certificates used to authenticate the
	// endpoint server.
	RootCAs []*x509.Certificate
}

// Client is used to fetch a bundle and metadata from a bundle endpoint
type Client interface {
	FetchBundle(context.Context) (*bundleutil.Bundle, *bundle.Metadata, error)
}

type client struct {
	c      ClientConfig
	client *http.Client
}

func NewClient(config ClientConfig) Client {
	spiffeID := config.EndpointSpiffeID
	if spiffeID == "" {
		spiffeID = idutil.ServerID(config.TrustDomain)
	}
	peer := &spiffe_tls.TLSPeer{
		SpiffeIDs:  []string{spiffeID},
		TrustRoots: util.NewCertPool(config.RootCAs...),
	}
	return &client{
		c: config,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: peer.NewTLSConfig(nil),
			},
		},
	}
}

func (c *client) FetchBundle(ctx context.Context) (*bundleutil.Bundle, *bundle.Metadata, error) {
	resp, err := c.client.Get(fmt.Sprintf("https://%s", c.c.EndpointAddress))
	if err != nil {
		return nil, nil, errs.New("failed to fetch bundle: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, errs.New("unexpected status %d fetching bundle: %s", resp.StatusCode, tryRead(resp.Body))
	}

	b, m, err := bundle.Decode(idutil.TrustDomainID(c.c.TrustDomain), resp.Body)
	if err != nil {
		return nil, nil, err
	}

	return b, m, nil
}

func tryRead(r io.Reader) string {
	b := make([]byte, 1024)
	n, _ := r.Read(b)
	return string(b[:n])
}
