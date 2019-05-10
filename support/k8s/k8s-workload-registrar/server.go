package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/zeebo/errs"
)

type ServerConfig struct {
	Log                    logrus.FieldLogger
	Handler                http.Handler
	Addr                   string
	CertPath               string
	KeyPath                string
	CaCertPath             string
	SkipClientVerification bool
}

type Server struct {
	config   ServerConfig
	listener net.Listener
	server   *http.Server
}

func NewServer(config ServerConfig) (*Server, error) {
	cert, err := tls.LoadX509KeyPair(config.CertPath, config.KeyPath)
	if err != nil {
		return nil, errs.New("unable to load server keypair: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	if !config.SkipClientVerification {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

		var err error
		tlsConfig.ClientCAs, err = loadCA(config.CaCertPath)
		if err != nil {
			return nil, err
		}
	}

	listener, err := net.Listen("tcp", config.Addr)
	if err != nil {
		return nil, errs.New("unable to listen: %v", err)
	}

	server := &http.Server{
		Handler:   config.Handler,
		TLSConfig: tlsConfig,
	}

	return &Server{
		config:   config,
		listener: listener,
		server:   server,
	}, nil
}

func (s *Server) Addr() net.Addr {
	return s.listener.Addr()
}

func (s *Server) Run(ctx context.Context) error {
	s.config.Log.WithFields(logrus.Fields{
		"addr":                     s.listener.Addr(),
		"skip_client_verification": s.config.SkipClientVerification,
	}).Info("Serving HTTPS")

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.server.ServeTLS(s.listener, "", "")
		s.listener.Close()
	}()

	select {
	case <-ctx.Done():
		// wait at most ten seconds for connections to drain before giving up.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()
		return errs.Wrap(s.server.Shutdown(shutdownCtx))
	case err := <-errCh:
		return errs.Wrap(err)
	}
}

func loadCA(path string) (*x509.CertPool, error) {
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errs.New("unable to read cacert file: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errs.New("unable to parse cacert file: %v", err)
	}
	return pool, nil
}
