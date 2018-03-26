package bundle

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
)

type showCLI struct {
	newRegistrationClient func(addr string) (registration.RegistrationClient, error)
	writer                io.Writer
}

type showConfig struct {
	// Address of SPIRE server
	addr string
}

// NewShowCommand creates a new "show" subcommand for "bundle" command.
func NewShowCommand() cli.Command {
	return &showCLI{
		writer: os.Stdout,
		newRegistrationClient: func(addr string) (registration.RegistrationClient, error) {
			return util.NewRegistrationClient(addr)
		},
	}
}

func (*showCLI) Synopsis() string {
	return "Prints CA bundle to standard out"
}

func (s *showCLI) Help() string {
	_, err := s.newConfig([]string{"-h"})
	return err.Error()
}

func (s *showCLI) Run(args []string) int {
	config, err := s.newConfig(args)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	c, err := s.newRegistrationClient(config.addr)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	bundle, err := c.FetchBundle(context.TODO(), &common.Empty{})
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	err = s.printBundleAsPEM(bundle)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	return 0
}

func (*showCLI) newConfig(args []string) (*showConfig, error) {
	f := flag.NewFlagSet("bundle show", flag.ContinueOnError)
	c := &showConfig{}
	f.StringVar(&c.addr, "serverAddr", util.DefaultServerAddr, "Address of the SPIRE server")
	return c, f.Parse(args)
}

func (s *showCLI) printBundleAsPEM(bundle *registration.Bundle) error {
	certs, err := x509.ParseCertificates(bundle.CaCerts)
	if err != nil {
		return fmt.Errorf("FAILED to parse bundle's ASN.1 DER data: %v", err)
	}

	for _, cert := range certs {
		err := pem.Encode(s.writer, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		if err != nil {
			return err
		}
	}
	return nil
}
