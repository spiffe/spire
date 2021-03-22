package entry

import (
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"google.golang.org/grpc/codes"

	"golang.org/x/net/context"
)

// NewDeleteCommand creates a new "delete" subcommand for "entry" command.
func NewDeleteCommand() cli.Command {
	return newDeleteCommand(common_cli.DefaultEnv)
}

func newDeleteCommand(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(deleteCommand))
}

type deleteCommand struct {
	// ID of the record to delete
	entryID string
}

func (*deleteCommand) Name() string {
	return "entry delete"
}

func (*deleteCommand) Synopsis() string {
	return "Deletes registration entries"
}

func (c *deleteCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.entryID, "entryID", "", "The Registration Entry ID of the record to delete")
}

func (c *deleteCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	if err := c.validate(); err != nil {
		return err
	}

	req := &entryv1.BatchDeleteEntryRequest{Ids: []string{c.entryID}}
	resp, err := serverClient.NewEntryClient().BatchDeleteEntry(ctx, req)
	if err != nil {
		return err
	}

	sts := resp.Results[0].Status
	switch sts.Code {
	case int32(codes.OK):
		env.Printf("Deleted entry with ID: %s\n", c.entryID)
		return nil
	default:
		return fmt.Errorf("failed to delete entry: %s", sts.Message)
	}
}

// Perform basic validation.
func (c *deleteCommand) validate() error {
	if c.entryID == "" {
		return errors.New("an entry ID is required")
	}

	return nil
}
