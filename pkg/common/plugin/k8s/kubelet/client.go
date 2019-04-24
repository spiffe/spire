package kubelet

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/spiffe/spire/pkg/agent/common/cgroups"
	"github.com/spiffe/spire/pkg/common/pemutil"
	corev1 "k8s.io/api/core/v1"
)

const (
	DefaultKubeletCAPath     = "/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	DefaultTokenPath         = "/run/secrets/kubernetes.io/serviceaccount/token"
	DefaultSecureKubeletPort = 10250
)

type Client interface {
	GetPodList() (*corev1.PodList, error)
	GetTransport() *http.Transport
	GetToken() string
	GetURL() url.URL
}

type client struct {
	Transport *http.Transport
	URL       url.URL
	Token     string
}

type ClientConfig struct {
	Secure                  bool
	Port                    int
	SkipKubeletVerification bool
	TokenPath               string
	CertificatePath         string
	PrivateKeyPath          string
	KubeletCAPath           string
	NodeName                string
	FS                      cgroups.FileSystem
}

func LoadClient(config *ClientConfig) (Client, error) {
	// The insecure client only needs to be loaded once.
	if !config.Secure {
		return &client{
			URL: url.URL{
				Scheme: "http",
				Host:   fmt.Sprintf("127.0.0.1:%d", config.Port),
			},
		}, nil
	}

	if config.Port <= 0 {
		config.Port = DefaultSecureKubeletPort
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.SkipKubeletVerification,
	}

	if config.FS == nil {
		config.FS = cgroups.OSFileSystem{}
	}

	var rootCAs *x509.CertPool
	var err error
	if !config.SkipKubeletVerification {
		rootCAs, err = loadKubeletCA(config.KubeletCAPath, config.FS)
		if err != nil {
			return nil, err
		}
	}

	switch {
	case config.SkipKubeletVerification:

	// When contacting the kubelet over localhost, skip the hostname validation.
	// Unfortunately Go does not make this straightforward. We disable
	// verification but supply a VerifyPeerCertificate that will be called
	// with the raw kubelet certs that we can verify directly.
	case config.NodeName == "":
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			var certs []*x509.Certificate
			for _, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return err
				}
				certs = append(certs, cert)
			}

			// this is improbable.
			if len(certs) == 0 {
				return errors.New("no certs presented by kubelet")
			}

			_, err := certs[0].Verify(x509.VerifyOptions{
				Roots:         rootCAs,
				Intermediates: newCertPool(certs[1:]),
			})
			return err
		}
	default:
		tlsConfig.RootCAs = rootCAs
	}

	var token string
	switch {
	case config.CertificatePath != "" && config.PrivateKeyPath != "":
		kp, err := loadX509KeyPair(config.CertificatePath, config.PrivateKeyPath, config.FS)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, *kp)
	case config.CertificatePath != "" && config.PrivateKeyPath == "":
		return nil, errors.New("the private key path is required with the certificate path")
	case config.CertificatePath == "" && config.PrivateKeyPath != "":
		return nil, errors.New("the certificate path is required with the private key path")
	case config.CertificatePath == "" && config.PrivateKeyPath == "":
		token, err = loadToken(config.TokenPath, config.FS)
		if err != nil {
			return nil, err
		}
	}

	host := config.NodeName
	if host == "" {
		host = "127.0.0.1"
	}

	client := &client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		URL: url.URL{
			Scheme: "https",
			Host:   fmt.Sprintf("%s:%d", host, config.Port),
		},
		Token: token,
	}
	// client.Config.LastReload = time.Now()
	return client, nil
}

func (c *client) GetTransport() *http.Transport {
	return c.Transport
}
func (c *client) GetToken() string {
	return c.Token
}
func (c *client) GetURL() url.URL {
	return c.URL
}

func (c *client) GetPodList() (*corev1.PodList, error) {
	url := c.URL
	url.Path = "/pods"
	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create request: %v", err)
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	client := &http.Client{}
	if c.Transport != nil {
		client.Transport = c.Transport
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to perform request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code on pods response: %d %s", resp.StatusCode, tryRead(resp.Body))
	}

	out := new(corev1.PodList)
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return nil, fmt.Errorf("unable to decode kubelet response: %v", err)
	}

	return out, nil
}

func loadKubeletCA(path string, fs cgroups.FileSystem) (*x509.CertPool, error) {
	if path == "" {
		path = DefaultKubeletCAPath
	}
	caPEM, err := readFile(path, fs)
	if err != nil {
		return nil, fmt.Errorf("unable to load kubelet CA: %v", err)
	}
	certs, err := pemutil.ParseCertificates(caPEM)
	if err != nil {
		return nil, fmt.Errorf("unable to parse kubelet CA: %v", err)
	}

	return newCertPool(certs), nil
}

func loadX509KeyPair(cert, key string, fs cgroups.FileSystem) (*tls.Certificate, error) {
	certPEM, err := readFile(cert, fs)
	if err != nil {
		return nil, fmt.Errorf("unable to load certificate: %v", err)
	}
	keyPEM, err := readFile(key, fs)
	if err != nil {
		return nil, fmt.Errorf("unable to load private key: %v", err)
	}
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("unable to load keypair: %v", err)
	}
	return &kp, nil
}

func loadToken(path string, fs cgroups.FileSystem) (string, error) {
	if path == "" {
		path = DefaultTokenPath
	}
	token, err := readFile(path, fs)
	if err != nil {
		return "", fmt.Errorf("unable to load token: %v", err)
	}
	return strings.TrimSpace(string(token)), nil
}

// readFile reads the contents of a file through the filesystem interface
func readFile(path string, fs cgroups.FileSystem) ([]byte, error) {
	f, err := fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ioutil.ReadAll(f)
}

func newCertPool(certs []*x509.Certificate) *x509.CertPool {
	certPool := x509.NewCertPool()
	for _, cert := range certs {
		certPool.AddCert(cert)
	}
	return certPool
}

func tryRead(r io.Reader) string {
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	return string(buf[:n])
}
