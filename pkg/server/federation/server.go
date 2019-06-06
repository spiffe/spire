package federation

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/bundleutil"
)

const (
	// defaultRefreshHint is the default refresh hint returned from the bundle
	// endpoint. Hard coding for now until we have a grasp on the right
	// strategy.
	defaultRefreshHint = time.Minute * 10
)

type BundleGetter interface {
	GetBundle(ctx context.Context) (*bundleutil.Bundle, error)
}

type BundleGetterFunc func(ctx context.Context) (*bundleutil.Bundle, error)

func (fn BundleGetterFunc) GetBundle(ctx context.Context) (*bundleutil.Bundle, error) {
	return fn(ctx)
}

type ServerCredsGetter interface {
	GetServerCreds() ([]*x509.Certificate, crypto.PrivateKey, error)
}

type ServerCredsGetterFunc func() ([]*x509.Certificate, crypto.PrivateKey, error)

func (fn ServerCredsGetterFunc) GetServerCreds() ([]*x509.Certificate, crypto.PrivateKey, error) {
	return fn()
}

type ServerConfig struct {
	Log          logrus.FieldLogger
	Address      string
	BundleGetter BundleGetter
	CredsGetter  ServerCredsGetter

	// test hooks
	listen func(network, address string) (net.Listener, error)
}

type Server struct {
	c ServerConfig
}

func NewServer(config ServerConfig) *Server {
	if config.listen == nil {
		config.listen = net.Listen
	}
	return &Server{
		c: config,
	}
}

func (s *Server) Run(ctx context.Context) error {
	// create the listener explicity instead of using ListenAndServeTLS since
	// it gives us the ability to use/inspect an ephemeral port during testing.
	listener, err := s.c.listen("tcp", s.c.Address)
	if err != nil {
		return err
	}

	server := &http.Server{
		Handler: http.HandlerFunc(s.serveHTTP),
		TLSConfig: &tls.Config{
			GetCertificate: s.getCertificate,
		},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ServeTLS(listener, "", "")
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		server.Close()
		return nil
	}
}

func (s *Server) serveHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		http.Error(w, "405 method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}

	bundle, err := s.c.BundleGetter.GetBundle(req.Context())
	if err != nil {
		s.c.Log.WithError(err).Error("unable to retrieve bundle")
		http.Error(w, "500 unable to retrieve bundle", http.StatusInternalServerError)
		return
	}

	// TODO: bundle sequence number?
	opts := []MarshalOption{
		WithRefreshHint(defaultRefreshHint),
	}

	bundleBytes, err := MarshalBundle(bundle, opts...)
	if err != nil {
		s.c.Log.WithError(err).Error("unable to marshal bundle")
		http.Error(w, "500 unable to marshal bundle", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(bundleBytes)
}

func (s *Server) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	chain, privateKey, err := s.c.CredsGetter.GetServerCreds()
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: chainDER(chain),
		PrivateKey:  privateKey,
	}, nil
}

func chainDER(chain []*x509.Certificate) [][]byte {
	var der [][]byte
	for _, cert := range chain {
		der = append(der, cert.Raw)
	}
	return der
}
