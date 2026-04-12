package bundle

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/spire/pkg/common/bundleutil"
)

type Getter interface {
	GetBundle(ctx context.Context) (*spiffebundle.Bundle, error)
}

type GetterFunc func(ctx context.Context) (*spiffebundle.Bundle, error)

func (fn GetterFunc) GetBundle(ctx context.Context) (*spiffebundle.Bundle, error) {
	return fn(ctx)
}

type ServerAuth interface {
	GetTLSConfig() *tls.Config
}

type ServerConfig struct {
	Log         logrus.FieldLogger
	Address     string
	Getter      Getter
	ServerAuth  ServerAuth
	RefreshHint time.Duration

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

func (s *Server) ListenAndServe(ctx context.Context) error {
	// create the listener explicitly instead of using ListenAndServeTLS since
	// it gives us the ability to use/inspect an ephemeral port during testing.
	listener, err := s.c.listen("tcp", s.c.Address)
	if err != nil {
		return err
	}

	// Set up the TLS config, setting TLS 1.2 as the minimum.
	tlsConfig := s.c.ServerAuth.GetTLSConfig()
	tlsConfig.MinVersion = tls.VersionTLS12

	server := &http.Server{
		Handler:           http.HandlerFunc(s.serveHTTP),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: time.Second * 10,
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

func (s *Server) WaitForListening() {
	// This method is a no-op for the bundle server since it does not have a
	// separate listening hook like the agent endpoints.
	// If needed, this can be implemented to signal when the server starts
	// listening.
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

	b, err := s.c.Getter.GetBundle(req.Context())
	if err != nil {
		s.c.Log.WithError(err).Error("Unable to retrieve local bundle")
		http.Error(w, "500 unable to retrieve local bundle", http.StatusInternalServerError)
		return
	}

	// TODO: bundle sequence number?
	opts := []bundleutil.MarshalOption{
		bundleutil.OverrideRefreshHint(s.c.RefreshHint),
	}

	jsonBytes, err := bundleutil.Marshal(b, opts...)
	if err != nil {
		s.c.Log.WithError(err).Error("Unable to marshal local bundle")
		http.Error(w, "500 unable to marshal local bundle", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(jsonBytes)
}

func chainDER(chain []*x509.Certificate) [][]byte {
	var der [][]byte
	for _, cert := range chain {
		der = append(der, cert.Raw)
	}
	return der
}
