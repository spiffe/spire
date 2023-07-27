package entry

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

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
	entriesIDs StringsFlag
	path       string
	env        *commoncli.Env
	printer    cliprinter.Printer
}

func (*deleteCommand) Name() string {
	return "entry delete"
}

func (*deleteCommand) Synopsis() string {
	return "Deletes registration entries"
}

func (c *deleteCommand) AppendFlags(f *flag.FlagSet) {
	f.Var(&c.entriesIDs, "entryID", "The Registration Entry ID of the record to delete. Can be used more than once")
	f.StringVar(&c.path, "data", "", "Path to a file containing deletion JSON (optional). If set to '-', read the JSON from stdin.")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, c.prettyPrintDelete)
}

func parseEntryDeleteJSON(path string) ([]string, error) {
	r := os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}

	dat, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	batchDeleteEntryRequest := &entryv1.BatchDeleteEntryRequest{}
	if err := json.Unmarshal(dat, batchDeleteEntryRequest); err != nil {
		return nil, err
	}
	return batchDeleteEntryRequest.Ids, nil
}

func (c *deleteCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	if err := c.validate(); err != nil {
		return err
	}

	var err error
	if c.path != "" {
		entriesIDs, err := parseEntryDeleteJSON(c.path)
		if err != nil {
			return err
		}
		for _, entryId := range entriesIDs {
			c.entriesIDs.Set(entryId)
		}
	}

	req := &entryv1.BatchDeleteEntryRequest{Ids: c.entriesIDs}
	resp, err := serverClient.NewEntryClient().BatchDeleteEntry(ctx, req)
	if err != nil {
		return err
	}

	return c.printer.PrintProto(resp)
}

// Perform basic validation.
func (c *deleteCommand) validate() error {
	if c.path != "" {
		return nil
	}

	if len(c.entriesIDs) < 1 {
		return errors.New("an entry ID is required")
	}

	return nil
}

func (c *deleteCommand) prettyPrintDelete(env *commoncli.Env, results ...interface{}) error {
	deleteResp, ok := results[0].(*entryv1.BatchDeleteEntryResponse)
	if !ok {
		return cliprinter.ErrInternalCustomPrettyFunc
	}

	var failed, succeded []*entryv1.BatchDeleteEntryResponse_Result
	for _, result := range deleteResp.Results {
		switch result.Status.Code {
		case int32(codes.OK):
			succeded = append(succeded, result)
		default:
			failed = append(failed, result)
		}
	}

	for _, result := range succeded {
		env.Printf("Deleted entry with ID: %s\n", result.Id)
	}

	for _, result := range failed {
		env.ErrPrintf("Failed to delete entry with ID %s (code: %s, msg: %q)\n",
			result.Id,
			codes.Code(result.Status.Code),
			result.Status.Message)
	}

	if len(failed) > 0 {
		return errors.New("failed to delete one or more entries")
	}

	return nil
}
