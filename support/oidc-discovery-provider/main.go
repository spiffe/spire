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

	var source JWKSSource
	switch {
	case config.RegistrationAPI != nil:
		source, err = NewRegistrationAPISource(RegistrationAPISourceConfig{
			Log:          log,
			SocketPath:   config.RegistrationAPI.SocketPath,
			PollInterval: config.RegistrationAPI.PollInterval,
		})
	case config.WorkloadAPI != nil:
		source, err = NewWorkloadAPISource(WorkloadAPISourceConfig{
			Log:          log,
			SocketPath:   config.WorkloadAPI.SocketPath,
			PollInterval: config.WorkloadAPI.PollInterval,
			TrustDomain:  config.WorkloadAPI.TrustDomain,
		})
	default:
		// This is defensive; LoadConfig should prevent this from happening.
		err = errs.New("no source has been configured")
	}
	if err != nil {
		return err
	}
	defer source.Close()

	var handler http.Handler = NewHandler(config.Domain, source)
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
		listener, err = net.Listen("unix", config.ListenSocketPath)
		if err != nil {
			return err
		}
		log.WithField("socket", config.ListenSocketPath).Info("Serving HTTP (unix)")
	default:
		listener = acmeListener(log, config)
		log.Info("Serving HTTPS via ACME")
	}

	return http.Serve(listener, handler)
}

func acmeListener(logger *log.Logger, config *Config) net.Listener {
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
		HostPolicy: autocert.HostWhitelist(config.Domain),
		Prompt: func(tosURL string) bool {
			logger.WithField("url", tosURL).Info("ACME Terms Of Service accepted")
			return true
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
