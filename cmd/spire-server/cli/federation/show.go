package federation

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	prototypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

func NewShowCommand() cli.Command {
	return newShowCommand(commoncli.DefaultEnv)
}

func newShowCommand(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &showCommand{env: env})
}

type showCommand struct {
	// Trust domain name of the federation relationship to show
	trustDomain string
	env         *commoncli.Env
	printer     cliprinter.Printer
}

func (c *showCommand) Name() string {
	return "federation show"
}

func (c *showCommand) Synopsis() string {
	return "Shows a dynamic federation relationship"
}

func (c *showCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.trustDomain, "trustDomain", "", "The trust domain name of the federation relationship to show")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, c.prettyPrintShow)
}

func (c *showCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	if c.trustDomain == "" {
		return errors.New("a trust domain name is required")
	}

	trustDomainClient := serverClient.NewTrustDomainClient()

	fr, err := trustDomainClient.GetFederationRelationship(ctx, &trustdomainv1.GetFederationRelationshipRequest{
		TrustDomain: c.trustDomain,
	})
	if err != nil {
		return fmt.Errorf("error showing federation relationship: %w", err)
	}

	return c.printer.PrintProto(fr)
}

func (c *showCommand) prettyPrintShow(env *commoncli.Env, results ...interface{}) error {
	fr, ok := results[0].(*prototypes.FederationRelationship)
	if !ok {
		return cliprinter.ErrInternalCustomPrettyFunc
	}
	env.Printf("Found a federation relationship with trust domain %s:\n\n", c.trustDomain)
	printFederationRelationship(fr, env.Printf)

	return nil
}
