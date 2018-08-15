package bundle

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/proto/api/registration"
)

// NewSetCommand creates a new "set" subcommand for "bundle" command.
func NewSetCommand() cli.Command {
	return newSetCommand(defaultEnv, newClients)
}

func newSetCommand(env *env, clientsMaker clientsMaker) cli.Command {
	return adaptCommand(env, clientsMaker, new(setCommand))
}

type setCommand struct {
	// SPIFFE ID of the trust bundle
	id string

	// Path to the bundle on disk (optional). If empty, reads from stdin.
	path string
}

func (c *setCommand) name() string {
	return "bundle set"
}

func (c *setCommand) synopsis() string {
	return "Sets bundle data"
}

func (c *setCommand) appendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.id, "id", "", "SPIFFE ID of the trust domain")
	fs.StringVar(&c.path, "path", "", "Path to the bundle data")
}

func (c *setCommand) run(ctx context.Context, env *env, clients *clients) error {
	if c.id == "" {
		return errors.New("id is required")
	}
	if err := idutil.ValidateSpiffeID(c.id, idutil.AllowAnyTrustDomain()); err != nil {
		return err
	}

	caCertsData, err := loadParamData(env.stdin, c.path)
	if err != nil {
		return fmt.Errorf("unable to load bundle data: %v", err)
	}

	certs, err := pemutil.ParseCertificates(caCertsData)
	if err != nil {
		return fmt.Errorf("invalid bundle data: %v", err)
	}
	var caCerts []byte
	for _, cert := range certs {
		caCerts = append(caCerts, cert.Raw...)
	}

	bundle := &registration.FederatedBundle{
		SpiffeId: c.id,
		CaCerts:  caCerts,
	}

	// pull the existing bundle to know if this should be a create or a update.
	// at some point it might be nice to have a create-or-update style API.
	_, err = clients.r.FetchFederatedBundle(ctx, &registration.FederatedBundleID{
		Id: c.id,
	})

	// assume that an error is because the bundle does not exist
	if err == nil {
		_, err = clients.r.UpdateFederatedBundle(ctx, bundle)
	} else {
		_, err = clients.r.CreateFederatedBundle(ctx, bundle)
	}
	if err != nil {
		return err
	}

	return env.Println("bundle set.")
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
