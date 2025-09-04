package entry

import (
	"context"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
)

// NewLockCommand creates a new "lock" subcommand for "entry" command.
func NewLockCommand() cli.Command {
	return newLockCommand(commoncli.DefaultEnv)
}

func newLockCommand(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &lockCommand{})
}

type lockCommand struct{}

func (c *lockCommand) Name() string {
	return "entry lock"
}

func (*lockCommand) Synopsis() string {
	return "Locks entry database to prevent additions or modifications."
}

func (c *lockCommand) AppendFlags(f *flag.FlagSet) {}

// Run executes all logic associated with a single invocation of the
// `spire-server entry lock` CLI command
func (c *lockCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	if _, err := serverClient.NewEntryClient().LockService(ctx, &entryv1.LockRequest{}); err != nil {
		return fmt.Errorf("error locking entry database: %w", err)
	}
	return nil
}
