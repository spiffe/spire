package entry

import (
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"google.golang.org/grpc/codes"

	"golang.org/x/net/context"
)

// NewDeleteCommand creates a new "delete" subcommand for "entry" command.
func NewDeleteCommand() cli.Command {
	return newDeleteCommand(commoncli.DefaultEnv)
}

func newDeleteCommand(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &deleteCommand{env: env})
}

type deleteCommand struct {
	// ID of the record to delete
	entryID string
	env     *commoncli.Env
	printer cliprinter.Printer
}

func (*deleteCommand) Name() string {
	return "entry delete"
}

func (*deleteCommand) Synopsis() string {
	return "Deletes registration entries"
}

func (c *deleteCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.entryID, "entryID", "", "The Registration Entry ID of the record to delete")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, c.prettyPrintDelete)
}

func (c *deleteCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	if err := c.validate(); err != nil {
		return err
	}

	req := &entryv1.BatchDeleteEntryRequest{Ids: []string{c.entryID}}
	resp, err := serverClient.NewEntryClient().BatchDeleteEntry(ctx, req)
	if err != nil {
		return err
	}

	return c.printer.PrintProto(resp)
}

// Perform basic validation.
func (c *deleteCommand) validate() error {
	if c.entryID == "" {
		return errors.New("an entry ID is required")
	}

	return nil
}

func (c *deleteCommand) prettyPrintDelete(env *commoncli.Env, results ...interface{}) error {
	deleteResp, ok := results[0].(*entryv1.BatchDeleteEntryResponse)
	if !ok {
		return cliprinter.ErrInternalCustomPrettyFunc
	}

	sts := deleteResp.Results[0].Status
	switch sts.Code {
	case int32(codes.OK):
		env.Printf("Deleted entry with ID: %s\n", c.entryID)
		return nil
	default:
		return fmt.Errorf("failed to delete entry: %s", sts.Message)
	}
}
