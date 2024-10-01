package upstreamauthority

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

// NewRevokeCommand creates a new "upstreamauthority revoke" subcommand for "upstreamauthority" command.
func NewRevokeCommand() cli.Command {
	return newRevokeCommand(commoncli.DefaultEnv)
}

// NewRevokeCommandWithEnv creates a new "upstreamauthority revoke" subcommand for "upstreamauthority" command
// using the environment specified
func NewRevokeCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &upstreamauthorityRevokeCommand{env: env})
}

func newRevokeCommand(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &upstreamauthorityRevokeCommand{env: env})
}

type upstreamauthorityRevokeCommand struct {
	subjectKeyID string
	printer      cliprinter.Printer
	env          *commoncli.Env
}

func (c *upstreamauthorityRevokeCommand) Name() string {
	return "upstreamauthority revoke"
}

func (*upstreamauthorityRevokeCommand) Synopsis() string {
	return "Revokes the previously active X.509 upstream authority by removing it from the bundle and propagating this update throughout the cluster"
}

func (c *upstreamauthorityRevokeCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.subjectKeyID, "subjectKeyID", "", "The X.509 Subject Key Identifier (or SKID) of the authority's CA certificate of the X.509 upstream authority to revoke")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, prettyPrintRevoke)
}

// Run executes all logic associated with a single invocation of the
// `spire-server upstreamauthority revoke` CLI command
func (c *upstreamauthorityRevokeCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	if err := c.validate(); err != nil {
		return err
	}

	client := serverClient.NewLocalAuthorityClient()
	resp, err := client.RevokeX509UpstreamAuthority(ctx, &localauthorityv1.RevokeX509UpstreamAuthorityRequest{
		SubjectKeyId: c.subjectKeyID,
	})
	if err != nil {
		return fmt.Errorf("could not revoke X.509 upstream authority: %w", err)
	}

	return c.printer.PrintProto(resp)
}

func prettyPrintRevoke(env *commoncli.Env, results ...any) error {
	r, ok := results[0].(*localauthorityv1.RevokeX509UpstreamAuthorityResponse)
	if !ok {
		return errors.New("internal error: cli printer; please report this bug")
	}

	env.Println("Revoked X.509 upstream authority:")
	env.Printf("  Subject Key ID: %s\n", r.UpstreamAuthoritySubjectKeyId)

	return nil
}

func (c *upstreamauthorityRevokeCommand) validate() error {
	if c.subjectKeyID == "" {
		return errors.New("the Subject Key ID of the X.509 upstream authority is required")
	}

	return nil
}
