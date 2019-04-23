package bundle

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
)

var (
	// this is the default environment used by commands
	defaultEnv = &env{
		stdin:  os.Stdin,
		stdout: os.Stdout,
		stderr: os.Stderr,
	}
)

type clients struct {
	r registration.RegistrationClient
}

type clientsMaker func(registrationUDSPath string) (*clients, error)

// newClients is the default client maker
func newClients(registrationUDSPath string) (*clients, error) {
	registrationClient, err := util.NewRegistrationClient(registrationUDSPath)
	if err != nil {
		return nil, err
	}

	return &clients{
		r: registrationClient,
	}, nil
}

// command is a common interface for commands in this package. the adapter
// can adapter this interface to the Command interface from github.com/mitchellh/cli.
type command interface {
	name() string
	synopsis() string
	appendFlags(*flag.FlagSet)
	run(context.Context, *env, *clients) error
}

type adapter struct {
	env          *env
	clientsMaker clientsMaker
	cmd          command

	registrationUDSPath string
	flags               *flag.FlagSet
}

// adaptCommand converts a command into one conforming to the Command interface from github.com/mitchellh/cli
func adaptCommand(env *env, clientsMaker clientsMaker, cmd command) *adapter {
	a := &adapter{
		clientsMaker: clientsMaker,
		cmd:          cmd,
		env:          env,
	}

	f := flag.NewFlagSet(cmd.name(), flag.ContinueOnError)
	f.SetOutput(env.stderr)
	f.StringVar(&a.registrationUDSPath, "registrationUDSPath", util.DefaultSocketPath, "Registration API UDS path")
	a.cmd.appendFlags(f)
	a.flags = f

	return a
}

func (a *adapter) Run(args []string) int {
	ctx := context.Background()

	if err := a.flags.Parse(args); err != nil {
		fmt.Fprintln(a.env.stderr, err)
		return 1
	}

	clients, err := a.clientsMaker(a.registrationUDSPath)
	if err != nil {
		fmt.Fprintln(a.env.stderr, err)
		return 1
	}

	if err := a.cmd.run(ctx, a.env, clients); err != nil {
		fmt.Fprintln(a.env.stderr, err)
		return 1
	}

	return 0
}

func (a *adapter) Help() string {
	return a.flags.Parse([]string{"-h"}).Error()
}

func (a *adapter) Synopsis() string {
	return a.cmd.synopsis()
}

// env provides input and output facilities to commands
type env struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

func (e *env) Printf(format string, args ...interface{}) error {
	_, err := fmt.Fprintf(e.stdout, format, args...)
	return err
}

func (e *env) Println(args ...interface{}) error {
	_, err := fmt.Fprintln(e.stdout, args...)
	return err
}

func (e *env) ErrPrintf(format string, args ...interface{}) error {
	_, err := fmt.Fprintf(e.stderr, format, args...)
	return err
}

func (e *env) ErrPrintln(args ...interface{}) error {
	_, err := fmt.Fprintln(e.stderr, args...)
	return err
}

// loadParamData loads the data from a parameter. If the parameter is empty then
// data is ready from "in", otherwise the parameter is used as a filename to
// read file contents.
func loadParamData(in io.Reader, fn string) ([]byte, error) {
	r := in
	if fn != "" {
		f, err := os.Open(fn)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}

	return ioutil.ReadAll(r)
}

func printCertificates(out io.Writer, certs []*common.Certificate) error {
	for _, cert := range certs {
		if err := printCertificate(out, cert); err != nil {
			return err
		}
	}
	return nil
}

func printCertificate(out io.Writer, cert *common.Certificate) error {
	return printCACertsPEM(out, cert.DerBytes)
}

func printCACertsPEM(out io.Writer, caCerts []byte) error {
	certs, err := x509.ParseCertificates(caCerts)
	if err != nil {
		return fmt.Errorf("unable to parse certificates ASN.1 DER data: %v", err)
	}

	for _, cert := range certs {
		if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return err
		}
	}
	return nil
}

func parseBundle(jwksBytes []byte) (*common.Bundle, error) {
	bundle, err := bundleutil.BundleFromJWKSBytes(jwksBytes)
	if err != nil {
		return nil, err
	}
	return bundle.Proto(), nil
}

func printBundle(out io.Writer, bundle *common.Bundle, header bool) error {
	if header {
		if _, err := fmt.Fprintf(out, headerFmt, bundle.TrustDomainId); err != nil {
			return err
		}
	}
	jwks, err := bundleutil.JWKSFromBundleProto(bundle)
	if err != nil {
		return err
	}

	jwksBytes, err := json.MarshalIndent(jwks, "", "\t")
	if err != nil {
		return errs.Wrap(err)
	}

	if _, err := fmt.Fprintln(out, string(jwksBytes)); err != nil {
		return errs.Wrap(err)
	}

	return nil
}
