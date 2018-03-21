package bundle

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
)

type ShowCLI struct{}

type ShowConfig struct {
	// Address of SPIRE server
	Addr string
}

func (*ShowCLI) Synopsis() string {
	return "Prints CA bundle to standard out"
}

func (s *ShowCLI) Help() string {
	_, err := s.newConfig([]string{"-h"})
	return err.Error()
}

func (s *ShowCLI) Run(args []string) int {

	config, err := s.newConfig(args)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	c, err := util.NewRegistrationClient(config.Addr)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	err = s.printBundlePEM(c)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	return 0
}

func (*ShowCLI) newConfig(args []string) (*ShowConfig, error) {
	f := flag.NewFlagSet("bundle show", flag.ContinueOnError)
	c := &ShowConfig{}
	f.StringVar(&c.Addr, "serverAddr", util.DefaultServerAddr, "Address of the SPIRE server")
	return c, f.Parse(args)
}

func (*ShowCLI) printBundlePEM(c registration.RegistrationClient) error {
	b, err := c.FetchBundle(context.TODO(), &common.Empty{})
	if err != nil {
		fmt.Println("FAILED to fetch server bundle")
		return err
	}

	printBundle(b)

	return nil
}

func printBundle(bundle *registration.Bundle) {
	certs, err := x509.ParseCertificates(bundle.Asn1Data)
	if err != nil {
		fmt.Println("FAILED to parse bundle's ASN.1 DER data")
	}

	for _, cert := range certs {
		pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
}
