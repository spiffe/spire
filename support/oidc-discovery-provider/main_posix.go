//go:build !windows

package main

import (
	"errors"
	"net"
	"os"
	"strings"

	"github.com/spiffe/spire/pkg/common/util"
)

func (c *Config) getWorkloadAPIAddr() (net.Addr, error) {
	return util.GetUnixAddrWithAbsPath(c.WorkloadAPI.SocketPath)
}

func (c *Config) getServingCertWorkloadAPIAddr() (net.Addr, error) {
	return util.GetUnixAddrWithAbsPath(c.ServingCertSource.WorkloadAPI.SocketPath)
}

func (c *Config) getServerAPITargetName() string {
	return c.ServerAPI.Address
}

// validateOS performs os specific validations of the configuration
func (c *Config) validateOS() (err error) {
	servingCertWorkloadAPI := c.servingCertWorkloadAPI()
	switch {
	case c.ACME == nil && c.ListenSocketPath == "" && c.ServingCertFile == nil && servingCertWorkloadAPI == nil && c.InsecureAddr == "":
		return errors.New("a serving_cert_source section, or either acme, serving_cert_file, insecure_addr or listen_socket_path must be configured")
	case servingCertWorkloadAPI != nil && (c.InsecureAddr != "" || c.ListenSocketPath != ""):
		return errors.New(`serving_cert_source "workload_api" is mutually exclusive with insecure_addr and listen_socket_path`)
	case c.ACME != nil && c.ServingCertFile != nil:
		return errors.New("acme and serving_cert_file are mutually exclusive")
	case c.ACME != nil && c.ListenSocketPath != "":
		return errors.New("listen_socket_path and the acme section are mutually exclusive")
	case c.ServingCertFile != nil && c.InsecureAddr != "":
		return errors.New("serving_cert_file and insecure_addr are mutually exclusive")
	case c.ServingCertFile != nil && c.ListenSocketPath != "":
		return errors.New("serving_cert_file and listen_socket_path are mutually exclusive")
	case c.ACME != nil && c.InsecureAddr != "":
		return errors.New("acme and insecure_addr are mutually exclusive")
	case c.InsecureAddr != "" && c.ListenSocketPath != "":
		return errors.New("insecure_addr and listen_socket_path are mutually exclusive")
	}

	if c.ServerAPI != nil {
		if c.ServerAPI.Address == "" {
			return errors.New("address must be configured in the server_api configuration section")
		}
		if !strings.HasPrefix(c.ServerAPI.Address, "unix:") {
			return errors.New("address must use the unix name system in the server_api configuration section")
		}
	}

	if c.WorkloadAPI != nil {
		if c.WorkloadAPI.SocketPath == "" {
			return errors.New("socket_path must be configured in the workload_api configuration section")
		}
	}

	if servingCertWorkloadAPI != nil && servingCertWorkloadAPI.SocketPath == "" {
		if c.WorkloadAPI == nil {
			return errors.New(`socket_path must be configured in the serving_cert_source "workload_api" configuration section`)
		}
		// Default to the Workload API used as the JWKS source.
		servingCertWorkloadAPI.SocketPath = c.WorkloadAPI.SocketPath
	}

	return nil
}

func listenLocal(c *Config) (net.Listener, error) {
	_ = os.Remove(c.ListenSocketPath)

	listener, err := net.Listen("unix", c.ListenSocketPath)
	if err != nil {
		return nil, err
	}

	if err := os.Chmod(c.ListenSocketPath, os.ModePerm); err != nil {
		return nil, err
	}

	return listener, nil
}
