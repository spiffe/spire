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

// NewX509ActivateCommand creates a new "x509 revoke" subcommand for "localauthority" command.
func NewX509RevokeCommand() cli.Command {
	return NewX509RevokeCommandWithEnv(commoncli.DefaultEnv)
}

// NewX509ActivateCommandWithEnv creates a new "x509 revoke" subcommand for "localauthority" command
// using the environment specified
func NewX509RevokeCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &x509RevokeCommand{env: env})
}

type x509RevokeCommand struct {
	authorityID string
	printer     cliprinter.Printer
	env         *commoncli.Env
}

func (c *x509RevokeCommand) Name() string {
	return "localauthority x509 revoke"
}

func (*x509RevokeCommand) Synopsis() string {
	return "Revokes the previously active X.509 authority by removing it from the bundle and propagating this update throughout the cluster"
}

func (c *x509RevokeCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.authorityID, "authorityID", "", "The authority ID of the X.509 authority to revoke")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, prettyPrintX509Revoke)
}

// Run executes all logic associated with a single invocation of the
// `spire-server localauthority x509 revoke` CLI command
func (c *x509RevokeCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	if err := c.validate(); err != nil {
		return err
	}

	client := serverClient.NewLocalAuthorityClient()
	resp, err := client.RevokeX509Authority(ctx, &localauthorityv1.RevokeX509AuthorityRequest{
		AuthorityId: c.authorityID,
	})
	if err != nil {
		return fmt.Errorf("could not revoke X.509 authority: %w", err)
	}

	return c.printer.PrintProto(resp)
}

func (c *x509RevokeCommand) validate() error {
	if c.authorityID == "" {
		return errors.New("an authority ID is required")
	}

	return nil
}

func prettyPrintX509Revoke(env *commoncli.Env, results ...any) error {
	r, ok := results[0].(*localauthorityv1.RevokeX509AuthorityResponse)
	if !ok {
		return errors.New("internal error: cli printer; please report this bug")
	}

	env.Println("Revoked X.509 authority:")
	if r.RevokedAuthority == nil {
		return errors.New("internal error: expected to have revoked X.509 authority information")
	}

	authoritycommon.PrettyPrintX509AuthorityState(env, r.RevokedAuthority)

	return nil
}
