package bundle

import (
	"context"
	"flag"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/proto/spire/common"
)

// NewShowCommand creates a new "show" subcommand for "bundle" command.
func NewShowCommand() cli.Command {
	return newShowCommand(defaultEnv, newClients)
}

func newShowCommand(env *env, clientsMaker clientsMaker) cli.Command {
	return adaptCommand(env, clientsMaker, new(showCommand))
}

type showCommand struct {
}

func (c *showCommand) name() string {
	return "bundle show"
}

func (c *showCommand) synopsis() string {
	return "Prints server CA bundle to stdout"
}

func (c *showCommand) appendFlags(fs *flag.FlagSet) {
}

func (c *showCommand) run(ctx context.Context, env *env, clients *clients) error {
	resp, err := clients.r.FetchBundle(ctx, &common.Empty{})
	if err != nil {
		return err
	}
	return printCertificates(env.stdout, resp.Bundle.RootCas)
}
