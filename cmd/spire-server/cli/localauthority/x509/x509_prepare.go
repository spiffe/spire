package x509

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/mitchellh/cli"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

// NewX509PrepareCommand creates a new "x509 prepare" subcommand for "localauthority" command.
func NewX509PrepareCommand() cli.Command {
	return NewX509PrepareCommandWithEnv(commoncli.DefaultEnv)
}

// NewX509PrepareCommandWithEnv creates a new "x509 prepare" subcommand for "localauthority" command
// using the environment specified
func NewX509PrepareCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &x509PrepareCommand{env: env})
}

type x509PrepareCommand struct {
	printer cliprinter.Printer
	env     *commoncli.Env
}

func (c *x509PrepareCommand) Name() string {
	return "localauthority x509 prepare"
}

func (*x509PrepareCommand) Synopsis() string {
	return "Prepares a new X.509 authority for use by generating a new key and injecting the resulting CA certificate into the bundle"
}

func (c *x509PrepareCommand) AppendFlags(f *flag.FlagSet) {
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, prettyPrintX509Prepare)
}

// Run executes all logic associated with a single invocation of the
// `spire-server localauthority x509 prepare` CLI command
func (c *x509PrepareCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	client := serverClient.NewLocalAuthorityClient()
	resp, err := client.PrepareX509Authority(ctx, &localauthorityv1.PrepareX509AuthorityRequest{})
	if err != nil {
		return fmt.Errorf("could not prepare X.509 authority: %w", err)
	}

	return c.printer.PrintProto(resp)
}

func prettyPrintX509Prepare(env *commoncli.Env, results ...any) error {
	r, ok := results[0].(*localauthorityv1.PrepareX509AuthorityResponse)
	if !ok {
		return errors.New("internal error: cli printer; please report this bug")
	}

	env.Println("Prepared X.509 authority:")
	if r.PreparedAuthority == nil {
		return errors.New("internal error: expected to have prepared X.509 authority information")
	}

	env.Printf("  Authority ID: %s\n", r.PreparedAuthority.AuthorityId)
	env.Printf("  Expires at: %s\n", time.Unix(r.PreparedAuthority.ExpiresAt, 0).UTC())

	return nil
}
