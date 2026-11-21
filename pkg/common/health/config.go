package health

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/hcl/hcl/token"
)

type Config struct {
	ListenerEnabled bool `hcl:"listener_enabled"`

	// Address and port to listen on, defaulting to localhost:80
	BindAddress string `hcl:"bind_address"`
	BindPort    string `hcl:"bind_port"`

	// Paths for /ready and /live
	ReadyPath string `hcl:"ready_path"`
	LivePath  string `hcl:"live_path"`

	// How often a healthy subsystem is checked, defaulting to one minute.
	// A failing subsystem is checked every second until it recovers.
	CheckInterval    time.Duration `hcl:"-"`
	RawCheckInterval string        `hcl:"check_interval"`

	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`
}

// getAddress returns an address suitable for use as http.Server.Addr.
func (c *Config) getAddress() string {
	host := "localhost"
	if c.BindAddress != "" {
		host = strings.Trim(c.BindAddress, "[]")
	}

	port := "80"
	if c.BindPort != "" {
		port = c.BindPort
	}

	return net.JoinHostPort(host, port)
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

// Details are additional data to be used when the system is ready
type Details struct {
	Message string `json:"message,omitempty"`
}

// Validate checks that the HTTP paths of the health check listener can be
// served. It does nothing when the listener is disabled, since the paths are
// not used then.
//
// http.ServeMux panics instead of returning an error when it is given a path
// it does not accept (for example one without a leading slash) or when the
// same path is registered twice, so the paths have to be checked before the
// checker is created.
func (c *Config) Validate() error {
	if !c.ListenerEnabled {
		return nil
	}

	readyPath, livePath := c.getReadyPath(), c.getLivePath()
	if readyPath == livePath {
		return fmt.Errorf("health_checks ready_path and live_path must be different, both are %q", readyPath)
	}
	if err := validatePath(readyPath); err != nil {
		return fmt.Errorf("invalid health_checks ready_path: %w", err)
	}
	if err := validatePath(livePath); err != nil {
		return fmt.Errorf("invalid health_checks live_path: %w", err)
	}
	return nil
}

// validatePath returns an error if http.ServeMux does not accept the path.
func validatePath(path string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	http.NewServeMux().HandleFunc(path, func(http.ResponseWriter, *http.Request) {})
	return nil
}

// ParseCheckInterval sets CheckInterval from RawCheckInterval.
func (c *Config) ParseCheckInterval() error {
	if c.RawCheckInterval == "" {
		c.CheckInterval = readyCheckInterval
		return nil
	}
	interval, err := time.ParseDuration(c.RawCheckInterval)
	if err != nil {
		return fmt.Errorf("could not parse check_interval: %w", err)
	}
	if interval <= readyCheckFailureInterval {
		return fmt.Errorf("check_interval must be longer than %s", readyCheckFailureInterval)
	}
	c.CheckInterval = interval
	return nil
}
