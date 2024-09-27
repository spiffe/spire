package x509

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/cmd/spire-server/cli/authoritycommon"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

// NewX509TaintCommand creates a new "x509 taint" subcommand for "localauthority" command.
func NewX509TaintCommand() cli.Command {
	return newX509TaintCommand(commoncli.DefaultEnv)
}

// NewX509TaintCommandWithEnv creates a new "x509 taint" subcommand for "localauthority" command
// using the environment specified
func NewX509TaintCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &x509TaintCommand{env: env})
}

func newX509TaintCommand(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &x509TaintCommand{env: env})
}

type x509TaintCommand struct {
	authorityID string
	printer     cliprinter.Printer
	env         *commoncli.Env
}

func (c *x509TaintCommand) Name() string {
	return "localauthority x509 taint"
}

func (*x509TaintCommand) Synopsis() string {
	return "Marks the previously active X.509 authority as being tainted"
}

func (c *x509TaintCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.authorityID, "authorityID", "", "The authority ID of the X.509 authority to taint")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, prettyPrintX509Taint)
}

// Run executes all logic associated with a single invocation of the
// `spire-server localauthority x509 taint` CLI command
func (c *x509TaintCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	if err := c.validate(); err != nil {
		return err
	}

	client := serverClient.NewLocalAuthorityClient()
	resp, err := client.TaintX509Authority(ctx, &localauthorityv1.TaintX509AuthorityRequest{
		AuthorityId: c.authorityID,
	})
	if err != nil {
		return fmt.Errorf("could not taint X.509 authority: %w", err)
	}

	return c.printer.PrintProto(resp)
}

func prettyPrintX509Taint(env *commoncli.Env, results ...any) error {
	r, ok := results[0].(*localauthorityv1.TaintX509AuthorityResponse)
	if !ok {
		return errors.New("internal error: cli printer; please report this bug")
	}

	env.Println("Tainted X.509 authority:")
	if r.TaintedAuthority == nil {
		return errors.New("internal error: expected to have tainted X.509 authority information")
	}

	authoritycommon.PrettyPrintX509AuthorityState(env, r.TaintedAuthority)

	return nil
}

func (c *x509TaintCommand) validate() error {
	if c.authorityID == "" {
		return errors.New("an authority ID is required")
	}

	return nil
}
