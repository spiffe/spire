package k8s

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/spiffe/spire/pkg/common/pemutil"
)

// kubeletTransportConfig holds the config items from which the http.Transport object
// is created; if any of them changes, a new transport must be created.
// The relevant logic (in podListFetcher) compares this struct using '==', hence
// care must be taken when making changes to the set of fields included here.
type kubeletTransportConfig struct {
	secure                  bool
	skipKubeletVerification bool
	nodeName                string
	port                    int
	caPEM                   string
	certificatePEM          string
	privateKeyPEM           string
}

type kubeletClient struct {
	transport       *http.Transport
	transportConfig kubeletTransportConfig
	endpoint        url.URL
	token           string
}

func newKubeletClient(config kubeletTransportConfig, token string) (*kubeletClient, error) {
	if !config.secure {
		return &kubeletClient{
			transportConfig: config,
			endpoint: url.URL{
				Scheme: "http",
				Host:   net.JoinHostPort("127.0.0.1", strconv.Itoa(config.port)),
			},
		}, nil
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.skipKubeletVerification, //nolint: gosec // intentionally configurable
	}

	var rootCAs *x509.CertPool
	if !config.skipKubeletVerification {
		certs, err := pemutil.ParseCertificates([]byte(config.caPEM))
		if err != nil {
			return nil, fmt.Errorf("unable to parse kubelet CA: %w", err)
		}
		rootCAs = newCertPool(certs)
	}

	switch {
	case config.skipKubeletVerification:
	case config.nodeName == "":
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.SessionTicketsDisabled = true
		tlsConfig.VerifyPeerCertificate = verifyKubeletCertificate(rootCAs)
	default:
		tlsConfig.RootCAs = rootCAs
	}

	if config.certificatePEM != "" {
		kp, err := tls.X509KeyPair([]byte(config.certificatePEM), []byte(config.privateKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("unable to load keypair: %w", err)
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, kp)
	}

	host := config.nodeName
	if host == "" {
		host = "127.0.0.1"
	}

	return &kubeletClient{
		transport:       &http.Transport{TLSClientConfig: tlsConfig},
		transportConfig: config,
		endpoint: url.URL{
			Scheme: "https",
			Host:   net.JoinHostPort(host, strconv.Itoa(config.port)),
		},
		token: token,
	}, nil
}

func (c *kubeletClient) getPodList(ctx context.Context) ([]byte, error) {
	url := c.endpoint
	url.Path = "/pods"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	client := &http.Client{}
	if c.transport != nil {
		client.Transport = c.transport
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to perform request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code on pods response: %d %s", resp.StatusCode, tryRead(resp.Body))
	}

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read pods response: %w", err)
	}
	return out, nil
}

func tryRead(r io.Reader) string {
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	return string(buf[:n])
}

func newCertPool(certs []*x509.Certificate) *x509.CertPool {
	certPool := x509.NewCertPool()
	for _, cert := range certs {
		certPool.AddCert(cert)
	}
	return certPool
}

func verifyKubeletCertificate(rootCAs *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		var certs []*x509.Certificate
		for _, rawCert := range rawCerts {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				return err
			}
			certs = append(certs, cert)
		}

		if len(certs) == 0 {
			return errors.New("no certs presented by kubelet")
		}

		_, err := certs[0].Verify(x509.VerifyOptions{
			Roots:         rootCAs,
			Intermediates: newCertPool(certs[1:]),
		})
		return err
	}
}
