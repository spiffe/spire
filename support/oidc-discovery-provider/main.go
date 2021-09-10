package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/zeebo/errs"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

var (
	configFlag = flag.String("config", "oidc-discovery-provider.conf", "configuration file")
)

func main() {
	flag.Parse()
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
	if config.Domain != "" {
		log.Warn("The domain configurable is deprecated and will be removed in a future release; use domains instead.")
		// Maintain backwards compatibility and allow requests over all domains
		// if configured with the deprecated `domain` configurable.
		domainPolicy = AllowAnyDomain()
	}

	var handler http.Handler = NewHandler(domainPolicy, source, config.AllowInsecureScheme)
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
	case config.ListenSocketPath != "":
		_ = os.Remove(config.ListenSocketPath)

		listener, err = net.Listen("unix", config.ListenSocketPath)
		if err != nil {
			return err
		}

		if err := os.Chmod(config.ListenSocketPath, os.ModePerm); err != nil {
			return err
		}

		log.WithField("socket", config.ListenSocketPath).Info("Serving HTTP (unix)")
	default:
		listener = acmeListener(log, config)
		log.Info("Serving HTTPS via ACME")
	}

	defer func() {
		err := listener.Close()
		log.Error(err)
	}()

	return http.Serve(listener, handler)
}

func newSource(log logrus.FieldLogger, config *Config) (JWKSSource, error) {
	switch {
	case config.ServerAPI != nil:
		return NewServerAPISource(ServerAPISourceConfig{
			Log:          log,
			Address:      config.ServerAPI.Address,
			PollInterval: config.ServerAPI.PollInterval,
		})
	case config.WorkloadAPI != nil:
		return NewWorkloadAPISource(WorkloadAPISourceConfig{
			Log:          log,
			SocketPath:   config.WorkloadAPI.SocketPath,
			PollInterval: config.WorkloadAPI.PollInterval,
			TrustDomain:  config.WorkloadAPI.TrustDomain,
		})
	default:
		// This is defensive; LoadConfig should prevent this from happening.
		return nil, errs.New("no source has been configured")
	}
}

func acmeListener(log logrus.FieldLogger, config *Config) net.Listener {
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
	return m.Listener()
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
