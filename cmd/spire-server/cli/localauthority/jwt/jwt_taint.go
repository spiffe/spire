package jwt

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

// NewJWTTaintCommand creates a new "jwt taint" subcommand for "localauthority" command.
func NewJWTTaintCommand() cli.Command {
	return newJWTTaintCommand(commoncli.DefaultEnv)
}

// NewJWTTaintCommandWithEnv creates a new "jwt taint" subcommand for "localauthority" command
// using the environment specified
func NewJWTTaintCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &jwtTaintCommand{env: env})
}

func newJWTTaintCommand(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &jwtTaintCommand{env: env})
}

type jwtTaintCommand struct {
	authorityID string
	printer     cliprinter.Printer
	env         *commoncli.Env
}

func (c *jwtTaintCommand) Name() string {
	return "localauthority jwt taint"
}

func (*jwtTaintCommand) Synopsis() string {
	return "Marks the previously active JWT authority as being tainted"
}

func (c *jwtTaintCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.authorityID, "authorityID", "", "The authority ID of the JWT authority to taint")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, prettyPrintJWTTaint)
}

// Run executes all logic associated with a single invocation of the
// `spire-server localauthority jwt taint` CLI command
func (c *jwtTaintCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	if err := c.validate(); err != nil {
		return err
	}

	client := serverClient.NewLocalAuthorityClient()
	resp, err := client.TaintJWTAuthority(ctx, &localauthorityv1.TaintJWTAuthorityRequest{
		AuthorityId: c.authorityID,
	})
	if err != nil {
		return fmt.Errorf("could not taint JWT authority: %w", err)
	}

	return c.printer.PrintProto(resp)
}

func prettyPrintJWTTaint(env *commoncli.Env, results ...any) error {
	r, ok := results[0].(*localauthorityv1.TaintJWTAuthorityResponse)
	if !ok {
		return errors.New("internal error: cli printer; please report this bug")
	}

	env.Println("Tainted JWT authority:")
	if r.TaintedAuthority == nil {
		return errors.New("internal error: expected to have tainted JWT authority information")
	}

	env.Printf("  Authority ID: %s\n", r.TaintedAuthority.AuthorityId)
	env.Printf("  Expires at: %s\n", time.Unix(r.TaintedAuthority.ExpiresAt, 0).UTC())

	return nil
}

func (c *jwtTaintCommand) validate() error {
	if c.authorityID == "" {
		return errors.New("an authority ID is required")
	}

	return nil
}
