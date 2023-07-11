package cache

import (
	"flag"
	"fmt"
	"time"

	"github.com/mitchellh/cli"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	commonutil "github.com/spiffe/spire/pkg/common/util"
	"golang.org/x/net/context"
)

const listEntriesRequestPageSize = 500

// NewShowCommand creates a new "show" subcommand for "entry" command.
func NewShowCommand() cli.Command {
	return newShowCommand(commoncli.DefaultEnv)
}

func newShowCommand(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &showCommand{env: env})
}

type showCommand struct {
	printer cliprinter.Printer
	env     *commoncli.Env
}

func (c *showCommand) Name() string {
	return "cache show"
}

func (*showCommand) Synopsis() string {
	return "Displays cached registration entries"
}

func (c *showCommand) AppendFlags(f *flag.FlagSet) {
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, prettyPrintShow)
}

// Run executes all logic associated with a single invocation of the
// `spire-server entry show` CLI command
func (c *showCommand) Run(ctx context.Context, env *commoncli.Env, serverClient util.ServerClient) error {
	resp, err := c.fetchEntries(ctx, serverClient.NewEntryClient())
	if err != nil {
		return err
	}

	commonutil.SortTypesEntries(resp.Entries)
	return c.printer.PrintProto(resp)
}

func (c *showCommand) fetchEntries(ctx context.Context, client entryv1.EntryClient) (*entryv1.ListCachedEntriesResponse, error) {
	listResp := &entryv1.ListCachedEntriesResponse{}

	pageToken := ""
	for {
		resp, err := client.ListCachedEntries(ctx, &entryv1.ListCachedEntriesRequest{
			PageSize:  listEntriesRequestPageSize,
			PageToken: pageToken,
		})
		if err != nil {
			return nil, fmt.Errorf("error fetching cached entries: %w", err)
		}
		listResp.Entries = append(listResp.Entries, resp.Entries...)
		if pageToken = resp.NextPageToken; pageToken == "" {
			break
		}
	}

	return listResp, nil
}

func prettyPrintShow(env *commoncli.Env, results ...interface{}) error {
	listResp, ok := results[0].(*entryv1.ListCachedEntriesResponse)
	if !ok {
		return cliprinter.ErrInternalCustomPrettyFunc
	}
	printEntries(listResp.Entries, env)
	return nil
}

func printEntries(entries []*types.Entry, env *commoncli.Env) {
	msg := fmt.Sprintf("Found %v ", len(entries))
	msg = util.Pluralizer(msg, "entry", "entries", len(entries))

	env.Println(msg)
	for _, e := range entries {
		printEntry(e, env.Printf)
	}
}

func printEntry(e *types.Entry, printf func(string, ...interface{}) error) {
	_ = printf("Entry ID         : %s\n", printableEntryID(e.Id))
	_ = printf("SPIFFE ID        : %s\n", protoToIDString(e.SpiffeId))
	_ = printf("Parent ID        : %s\n", protoToIDString(e.ParentId))
	_ = printf("Revision         : %d\n", e.RevisionNumber)

	if e.Downstream {
		_ = printf("Downstream       : %t\n", e.Downstream)
	}

	if e.X509SvidTtl == 0 {
		_ = printf("X509-SVID TTL    : default\n")
	} else {
		_ = printf("X509-SVID TTL    : %d\n", e.X509SvidTtl)
	}

	if e.JwtSvidTtl == 0 {
		_ = printf("JWT-SVID TTL     : default\n")
	} else {
		_ = printf("JWT-SVID TTL     : %d\n", e.JwtSvidTtl)
	}

	if e.ExpiresAt != 0 {
		_ = printf("Expiration time  : %s\n", time.Unix(e.ExpiresAt, 0).UTC())
	}

	for _, s := range e.Selectors {
		_ = printf("Selector         : %s:%s\n", s.Type, s.Value)
	}
	for _, id := range e.FederatesWith {
		_ = printf("FederatesWith    : %s\n", id)
	}
	for _, dnsName := range e.DnsNames {
		_ = printf("DNS name         : %s\n", dnsName)
	}

	// admin is rare, so only show admin if true to keep
	// from muddying the output.
	if e.Admin {
		_ = printf("Admin            : %t\n", e.Admin)
	}

	if e.StoreSvid {
		_ = printf("StoreSvid        : %t\n", e.StoreSvid)
	}

	if e.Hint != "" {
		_ = printf("Hint             : %s\n", e.Hint)
	}

	_ = printf("\n")
}

func printableEntryID(id string) string {
	if id == "" {
		return "(none)"
	}
	return id
}

// protoToIDString converts a SPIFFE ID from the given *types.SPIFFEID to string
func protoToIDString(id *types.SPIFFEID) string {
	if id == nil {
		return ""
	}
	return fmt.Sprintf("spiffe://%s%s", id.TrustDomain, id.Path)
}
