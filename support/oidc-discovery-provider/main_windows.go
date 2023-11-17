//go:build windows
// +build windows

package main

import (
	"fmt"
	"net"
	"path/filepath"

	"github.com/Microsoft/go-winio"
	"github.com/spiffe/spire/pkg/common/namedpipe"
	"github.com/spiffe/spire/pkg/common/sddl"
	"github.com/zeebo/errs"
)

func (c *Config) getWorkloadAPIAddr() (net.Addr, error) {
	return namedpipe.AddrFromName(c.WorkloadAPI.Experimental.NamedPipeName), nil
}

func (c *Config) getServerAPITargetName() string {
	return fmt.Sprintf(`\\.\%s`, filepath.Join("pipe", c.ServerAPI.Experimental.NamedPipeName))
}

// validateOS performs os specific validations of the configuration
func (c *Config) validateOS() (err error) {
	switch {
	case c.ACME == nil && c.Experimental.ListenNamedPipeName == "" && c.ServingCertFile == nil && c.InsecureAddr == "":
		return errs.New("either acme, serving_cert_file, insecure_addr or listen_named_pipe_name must be configured")
	case c.ACME != nil && c.ServingCertFile != nil:
		return errs.New("acme and serving_cert_file are mutually exclusive")
	case c.ACME != nil && c.Experimental.ListenNamedPipeName != "":
		return errs.New("listen_named_pipe_name and the acme section are mutually exclusive")
	case c.ACME != nil && c.InsecureAddr != "":
		return errs.New("acme and insecure_addr are mutually exclusive")
	case c.ServingCertFile != nil && c.InsecureAddr != "":
		return errs.New("serving_cert_file and insecure_addr are mutually exclusive")
	case c.ServingCertFile != nil && c.Experimental.ListenNamedPipeName != "":
		return errs.New("serving_cert_file and listen_named_pipe_name are mutually exclusive")
	case c.InsecureAddr != "" && c.Experimental.ListenNamedPipeName != "":
		return errs.New("insecure_addr and listen_named_pipe_name are mutually exclusive")
	}
	if c.ServerAPI != nil {
		if c.ServerAPI.Experimental.NamedPipeName == "" {
			return errs.New("named_pipe_name must be configured in the server_api configuration section")
		}
	}

	if c.WorkloadAPI != nil {
		if c.WorkloadAPI.Experimental.NamedPipeName == "" {
			return errs.New("named_pipe_name must be configured in the workload_api configuration section")
		}
	}

	return nil
}

func listenLocal(c *Config) (net.Listener, error) {
	return winio.ListenPipe(namedpipe.AddrFromName(c.Experimental.ListenNamedPipeName).String(),
		&winio.PipeConfig{SecurityDescriptor: sddl.PrivateListener})
}
