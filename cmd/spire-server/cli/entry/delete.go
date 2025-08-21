package entry

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/mitchellh/cli"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	serverutil "github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"github.com/spiffe/spire/pkg/common/util"
	"google.golang.org/grpc/codes"
)

// NewDeleteCommand creates a new "delete" subcommand for "entry" command.
func NewDeleteCommand() cli.Command {
	return newDeleteCommand(commoncli.DefaultEnv)
}

func newDeleteCommand(env *commoncli.Env) cli.Command {
	return serverutil.AdaptCommand(env, &deleteCommand{env: env})
}

type deleteCommand struct {
	// ID of the record to delete
	entryID string
	file    string
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
	f.StringVar(&c.entryID, "entryID", "", "The Registration Entry ID of the record to delete.")
	f.StringVar(&c.file, "file", "", "Path to a file containing a JSON structure for batch deletion (optional). If set to '-', read from stdin.")
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

func (c *deleteCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient serverutil.ServerClient) error {
	if err := c.validate(); err != nil {
		return err
	}

	var err error
	entriesIDs := []string{}
	if c.file != "" {
		entriesIDs, err = parseEntryDeleteJSON(c.file)
		if err != nil {
			return err
		}
	} else {
		entriesIDs = append(entriesIDs, c.entryID)
	}

	req := &entryv1.BatchDeleteEntryRequest{Ids: entriesIDs}
	resp, err := serverClient.NewEntryClient().BatchDeleteEntry(ctx, req)
	if err != nil {
		return err
	}

	return c.printer.PrintProto(resp)
}

// Perform basic validation.
func (c *deleteCommand) validate() error {
	if c.file != "" {
		return nil
	}

	if c.entryID == "" {
		return errors.New("an entry ID is required")
	}

	return nil
}

func (c *deleteCommand) prettyPrintDelete(env *commoncli.Env, results ...any) error {
	deleteResp, ok := results[0].(*entryv1.BatchDeleteEntryResponse)
	if !ok {
		return cliprinter.ErrInternalCustomPrettyFunc
	}

	var failed, succeeded []*entryv1.BatchDeleteEntryResponse_Result
	for _, result := range deleteResp.Results {
		switch result.Status.Code {
		case int32(codes.OK):
			succeeded = append(succeeded, result)
		default:
			failed = append(failed, result)
		}
	}

	for _, result := range succeeded {
		env.Printf("Deleted entry with ID: %s\n", result.Id)
	}

	if len(succeeded) > 0 {
		env.Printf("\n\n")
	}

	for _, result := range failed {
		env.ErrPrintf("Failed to delete entry with ID %s (code: %s, msg: %q)\n",
			result.Id,
			util.MustCast[codes.Code](result.Status.Code),
			result.Status.Message)
	}

	if len(failed) > 0 {
		env.Printf("\n\n")
		summaryMsg := fmt.Sprintf("Deleted %d entries successfully, but failed to delete %d entries", len(succeeded), len(failed))

		if len(succeeded) == 0 {
			summaryMsg = fmt.Sprintf("Failed to delete %d entries", len(failed))
		}

		env.Printf("%s", summaryMsg)
		return errors.New("failed to delete one or more entries")
	}

	env.Printf("Deleted %d entries successfully", len(succeeded))

	return nil
}
