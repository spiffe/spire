package health

import (
	"fmt"
)

type Config struct {
	ListenerEnabled bool `hcl:"listener_enabled"`

	// Address and port to listen on, defaulting to localhost:80
	BindAddress string `hcl:"bind_address"`
	BindPort    string `hcl:"bind_port"`

	// Paths for /ready and /live
	ReadyPath string `hcl:"ready_path"`
	LivePath  string `hcl:"live_path"`
}

// getReadyPath returns the configured value or a default
func (c *Config) getReadyPath() string {
	if c.ReadyPath == "" {
		return "/ready"
	}

	return c.ReadyPath
}

// getLivePath returns the configured value or a default
func (c *Config) getLivePath() string {
	if c.LivePath == "" {
		return "/live"
	}

	return c.LivePath
}

// getAddress returns an address suitable for use as http.Server.Addr, or nil if not configured with
// a port to listen on
func (c *Config) getAddress() *string {
	if c.ListenerEnabled {
		host := "localhost"
		if c.BindAddress != "" {
			host = c.BindAddress
		}

		port := "80"
		if c.BindPort != "" {
			port = c.BindPort
		}

		address := fmt.Sprintf("%s:%s", host, port)
		return &address
	}
	return nil
}
