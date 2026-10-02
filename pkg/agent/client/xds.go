package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	xdsbootstrap "google.golang.org/grpc/xds/bootstrap"
)

const (
	xdsBootstrapFileEnv   = "GRPC_XDS_BOOTSTRAP"
	xdsBootstrapConfigEnv = "GRPC_XDS_BOOTSTRAP_CONFIG"
)

type xdsBootstrap struct {
	XDSServers  []xdsServer `json:"xds_servers"`
	Authorities map[string]struct {
		XDSServers []xdsServer `json:"xds_servers"`
	} `json:"authorities"`
}

type xdsServer struct {
	ServerURI    string `json:"server_uri"`
	ChannelCreds []struct {
		Type string `json:"type"`
	} `json:"channel_creds"`
}

// ValidateXDSBootstrap ensures every xDS management server in the gRPC xDS
// bootstrap is either local (unix socket or loopback) or reached over TLS.
// The bootstrap is located the same way gRPC does.
func ValidateXDSBootstrap() error {
	var data []byte
	switch {
	case os.Getenv(xdsBootstrapFileEnv) != "":
		path := os.Getenv(xdsBootstrapFileEnv)
		var err error
		data, err = os.ReadFile(path) //nolint:gosec // operator-supplied path, as read by gRPC
		if err != nil {
			return fmt.Errorf("failed to read xDS bootstrap %q: %w", path, err)
		}
	case os.Getenv(xdsBootstrapConfigEnv) != "":
		data = []byte(os.Getenv(xdsBootstrapConfigEnv))
	default:
		return fmt.Errorf("xDS bootstrap not configured; set %s or %s", xdsBootstrapFileEnv, xdsBootstrapConfigEnv)
	}
	return validateXDSBootstrap(data)
}

func validateXDSBootstrap(data []byte) error {
	var b xdsBootstrap
	if err := json.Unmarshal(data, &b); err != nil {
		return fmt.Errorf("failed to parse xDS bootstrap: %w", err)
	}
	if len(b.XDSServers) == 0 {
		return errors.New("xDS bootstrap has no xds_servers")
	}

	servers := b.XDSServers
	for _, a := range b.Authorities {
		servers = append(servers, a.XDSServers...)
	}
	for _, s := range servers {
		if isLocalXDSServer(s.ServerURI) {
			continue
		}
		if creds := selectedChannelCreds(s); creds != "tls" {
			return fmt.Errorf("xDS server %q is not local and uses %q channel credentials; must use \"tls\"", s.ServerURI, creds)
		}
	}
	return nil
}

// selectedChannelCreds mirrors gRPC: the first supported type is used.
func selectedChannelCreds(s xdsServer) string {
	for _, cc := range s.ChannelCreds {
		if xdsbootstrap.GetChannelCredentials(cc.Type) != nil {
			return cc.Type
		}
	}
	return ""
}

func isLocalXDSServer(uri string) bool {
	if u, err := url.Parse(uri); err == nil {
		switch u.Scheme {
		case "unix", "unix-abstract":
			return true
		case "dns", "passthrough":
			// A dns authority names a remote DNS server.
			if u.Host != "" {
				return false
			}
			endpoint := u.Opaque
			if endpoint == "" {
				endpoint = strings.TrimPrefix(u.Path, "/")
			}
			return isLoopbackHost(endpoint)
		}
	}
	// No scheme: gRPC defaults to dns.
	return isLoopbackHost(uri)
}

func isLoopbackHost(hostPort string) bool {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
