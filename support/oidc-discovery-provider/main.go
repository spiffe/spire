package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/version"
	"github.com/zeebo/errs"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

var (
	versionFlag = flag.Bool("version", false, "print version")
	configFlag  = flag.String("config", "oidc-discovery-provider.conf", "configuration file")
)

func main() {
	flag.Parse()

	if *versionFlag {
		fmt.Println(version.Version())
		os.Exit(0)
	}

	if err := run(*configFlag); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	config, err := LoadConfig(configPath)
	if err != nil {
		return err
	}

	log, err := log.NewLogger(log.WithLevel(config.LogLevel), log.WithFormat(config.LogFormat), log.WithOutputFile(config.LogPath))
	if err != nil {
		return errs.Wrap(err)
	}
	defer log.Close()

	source, err := newSource(log, config)
	if err != nil {
		return err
	}
	defer source.Close()

	domainPolicy, err := DomainAllowlist(config.Domains...)
	if err != nil {
		return err
	}

	var handler http.Handler = NewHandler(log, domainPolicy, source, config.AllowInsecureScheme, config.SetKeyUse)
	if config.LogRequests {
		log.Info("Logging all requests")
		handler = logHandler(log, handler)
	}

	var listener net.Listener

	switch {
	case config.InsecureAddr != "":
		listener, err = net.Listen("tcp", config.InsecureAddr)
		if err != nil {
			return err
		}
		log.WithField("address", config.InsecureAddr).Warn("Serving HTTP (insecure)")
	case config.ListenSocketPath != "" || config.Experimental.ListenNamedPipeName != "":
		listener, err = listenLocal(config)
		if err != nil {
			return err
		}
		log.WithFields(logrus.Fields{
			telemetry.Network: listener.Addr().Network(),
			telemetry.Address: listener.Addr().String(),
		}).Info("Serving HTTP")
	default:
		listener, err = newACMEListener(log, config)
		if err != nil {
			return err
		}
		log.Info("Serving HTTPS via ACME")
	}

	defer func() {
		err := listener.Close()
		log.Error(err)
	}()

	if config.HealthChecks != nil {
		go func() {
			server := &http.Server{
				Addr:              fmt.Sprintf(":%d", config.HealthChecks.BindPort),
				Handler:           NewHealthChecksHandler(source, config),
				ReadHeaderTimeout: 10 * time.Second,
			}
			log.Error(server.ListenAndServe())
		}()
	}

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return server.Serve(listener)
}

func newSource(log logrus.FieldLogger, config *Config) (JWKSSource, error) {
	switch {
	case config.ServerAPI != nil:
		return NewServerAPISource(ServerAPISourceConfig{
			Log:          log,
			GRPCTarget:   config.getServerAPITargetName(),
			PollInterval: config.ServerAPI.PollInterval,
		})
	case config.WorkloadAPI != nil:
		workloadAPIAddr, err := config.getWorkloadAPIAddr()
		if err != nil {
			return nil, errs.New(err.Error())
		}
		return NewWorkloadAPISource(WorkloadAPISourceConfig{
			Log:          log,
			Addr:         workloadAPIAddr,
			PollInterval: config.WorkloadAPI.PollInterval,
			TrustDomain:  config.WorkloadAPI.TrustDomain,
		})
	default:
		// This is defensive; LoadConfig should prevent this from happening.
		return nil, errs.New("no source has been configured")
	}
}

func newACMEListener(log logrus.FieldLogger, config *Config) (net.Listener, error) {
	var cache autocert.Cache
	if config.ACME.CacheDir != "" {
		cache = autocert.DirCache(config.ACME.CacheDir)
	}

	m := autocert.Manager{
		Cache: cache,
		Client: &acme.Client{
			UserAgent:    "SPIRE OIDC Discovery Provider",
			DirectoryURL: config.ACME.DirectoryURL,
		},
		Email:      config.ACME.Email,
		HostPolicy: autocert.HostWhitelist(config.Domains...),
		Prompt: func(tosURL string) bool {
			log.WithField("url", tosURL).Info("ACME Terms Of Service accepted")
			return config.ACME.ToSAccepted
		},
	}

	tlsConfig := m.TLSConfig()
	tlsConfig.MinVersion = tls.VersionTLS12

	tcpListener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: 443})
	if err != nil {
		return nil, fmt.Errorf("failed to create an ACME listener: %w", err)
	}

	return &acmeListener{TCPListener: tcpListener, conf: tlsConfig}, nil
}

func logHandler(log logrus.FieldLogger, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.WithFields(logrus.Fields{
			"remote-addr": r.RemoteAddr,
			"method":      r.Method,
			"url":         r.URL,
			"user-agent":  r.UserAgent,
		}).Debug("Incoming request")
		handler.ServeHTTP(w, r)
	})
}

// This code was borrowed and modified from the
// golang.org/x/crypto/acme/autocert package. It wraps a normal TCP listener to
// set a reasonable keepalive on the TCP connection in the same vein as the
// net/http package.
type acmeListener struct {
	*net.TCPListener
	conf *tls.Config
}

func (ln *acmeListener) Accept() (net.Conn, error) {
	conn, err := ln.TCPListener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	_ = conn.SetKeepAlive(true)
	_ = conn.SetKeepAlivePeriod(3 * time.Minute)
	return tls.Server(conn, ln.conf), nil
}
