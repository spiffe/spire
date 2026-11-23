//go:build windows

package main

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"

	"github.com/Microsoft/go-winio"
	"github.com/spiffe/spire/pkg/common/namedpipe"
	"github.com/spiffe/spire/pkg/common/sddl"
)

func (c *Config) getWorkloadAPIAddr() (net.Addr, error) {
	return namedpipe.AddrFromName(c.WorkloadAPI.Experimental.NamedPipeName), nil
}

func (c *Config) getServingCertWorkloadAPIAddr() (net.Addr, error) {
	return namedpipe.AddrFromName(c.ServingCertSource.WorkloadAPI.Experimental.NamedPipeName), nil
}

func (c *Config) getServerAPITargetName() string {
	return fmt.Sprintf(`\\.\%s`, filepath.Join("pipe", c.ServerAPI.Experimental.NamedPipeName))
}

// validateOS performs os specific validations of the configuration
func (c *Config) validateOS() (err error) {
	servingCertWorkloadAPI := c.servingCertWorkloadAPI()
	switch {
	case c.ACME == nil && c.Experimental.ListenNamedPipeName == "" && c.ServingCertFile == nil && servingCertWorkloadAPI == nil && c.InsecureAddr == "":
		return errors.New("one of serving_cert_source, acme, serving_cert_file, insecure_addr or listen_named_pipe_name must be configured")
	case servingCertWorkloadAPI != nil && (c.InsecureAddr != "" || c.Experimental.ListenNamedPipeName != ""):
		return errors.New(`serving_cert_source "workload_api" is mutually exclusive with insecure_addr and listen_named_pipe_name`)
	case c.ACME != nil && c.ServingCertFile != nil:
		return errors.New("acme and serving_cert_file are mutually exclusive")
	case c.ACME != nil && c.Experimental.ListenNamedPipeName != "":
		return fmt.Errorf("listen_named_pipe_name and the %s section are mutually exclusive", c.acmeSectionName())
	case c.ACME != nil && c.InsecureAddr != "":
		return fmt.Errorf("%s and insecure_addr are mutually exclusive", c.acmeSectionName())
	case c.ServingCertFile != nil && c.InsecureAddr != "":
		return fmt.Errorf("%s and insecure_addr are mutually exclusive", c.certFileSectionName())
	case c.ServingCertFile != nil && c.Experimental.ListenNamedPipeName != "":
		return fmt.Errorf("%s and listen_named_pipe_name are mutually exclusive", c.certFileSectionName())
	case c.InsecureAddr != "" && c.Experimental.ListenNamedPipeName != "":
		return errors.New("insecure_addr and listen_named_pipe_name are mutually exclusive")
	}
	if c.ServerAPI != nil {
		if c.ServerAPI.Experimental.NamedPipeName == "" {
			return errors.New("named_pipe_name must be configured in the server_api configuration section")
		}
	}

	if c.WorkloadAPI != nil {
		if c.WorkloadAPI.Experimental.NamedPipeName == "" {
			return errors.New("named_pipe_name must be configured in the workload_api configuration section")
		}
	}

	if servingCertWorkloadAPI != nil && servingCertWorkloadAPI.Experimental.NamedPipeName == "" {
		if c.WorkloadAPI == nil {
			return errors.New(`named_pipe_name must be configured in the serving_cert_source "workload_api" configuration section`)
		}
		// Default to the Workload API used as the JWKS source.
		servingCertWorkloadAPI.Experimental.NamedPipeName = c.WorkloadAPI.Experimental.NamedPipeName
	}

	return nil
}

func listenLocal(c *Config) (net.Listener, error) {
	return winio.ListenPipe(namedpipe.AddrFromName(c.Experimental.ListenNamedPipeName).String(),
		&winio.PipeConfig{SecurityDescriptor: sddl.PrivateListener})
}
