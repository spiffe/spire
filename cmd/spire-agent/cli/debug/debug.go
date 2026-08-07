package debug

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/mitchellh/cli"
	debugv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/debug/v1"
	"github.com/spiffe/spire/cmd/spire-agent/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

func NewGetInfoCommand() cli.Command {
	return NewGetInfoCommandWithEnv(commoncli.DefaultEnv)
}

func NewGetInfoCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &getInfoCommand{env: env})
}

type getInfoCommand struct {
	env     *commoncli.Env
	printer cliprinter.Printer
}

func (*getInfoCommand) Name() string {
	return "debug getinfo"
}

func (*getInfoCommand) Synopsis() string {
	return "Prints debug information about the agent"
}

func (c *getInfoCommand) AppendFlags(fs *flag.FlagSet) {
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, prettyPrintGetInfo)
}

func (c *getInfoCommand) Run(ctx context.Context, _ *commoncli.Env, client util.AgentClient) error {
	debugClient := client.NewDebugClient()
	resp, err := debugClient.GetInfo(ctx, &debugv1.GetInfoRequest{})
	if err != nil {
		return err
	}
	return c.printer.PrintProto(resp)
}

func prettyPrintGetInfo(env *commoncli.Env, results ...any) error {
	resp, ok := results[0].(*debugv1.GetInfoResponse)
	if !ok {
		return cliprinter.ErrInternalCustomPrettyFunc
	}

	env.Printf("Agent Debug Info:\n")
	env.Printf("  Uptime:                          %s\n", (time.Duration(resp.Uptime) * time.Second).String())
	env.Printf("  Last Sync Success:               %s\n", formatLastSync(resp.LastSyncSuccess))
	env.Printf("  Cached X.509 SVIDs:              %d\n", resp.CachedX509SvidsCount)
	env.Printf("  Cached JWT SVIDs:                %d\n", resp.CachedJwtSvidsCount)
	env.Printf("  Cached SVID Store X.509 SVIDs:   %d\n", resp.CachedSvidstoreX509SvidsCount)

	if len(resp.SvidChain) > 0 {
		env.Printf("  SVID Chain:\n")
		for i, cert := range resp.SvidChain {
			env.Printf("    [%d] SPIFFE ID:  %s\n", i, spiffeIDString(cert))
			env.Printf("        Subject:    %s\n", cert.Subject)
			env.Printf("        Expires At: %s\n", time.Unix(cert.ExpiresAt, 0).UTC().Format(time.RFC3339))
		}
	}

	return nil
}

func formatLastSync(lastSyncSuccess int64) string {
	if lastSyncSuccess == 0 {
		return "(never)"
	}
	return time.Unix(lastSyncSuccess, 0).UTC().Format(time.RFC3339)
}

func spiffeIDString(cert *debugv1.GetInfoResponse_Cert) string {
	if cert.Id == nil {
		return "(none)"
	}
	return fmt.Sprintf("spiffe://%s%s", cert.Id.TrustDomain, cert.Id.Path)
}
