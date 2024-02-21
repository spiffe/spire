package bundle

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"google.golang.org/grpc/codes"
)

const (
	deleteBundleRestrict   = "restrict"
	deleteBundleDissociate = "dissociate"
	deleteBundleDelete     = "delete"
)

// NewDeleteCommand creates a new "delete" subcommand for "bundle" command.
func NewDeleteCommand() cli.Command {
	return newDeleteCommand(commoncli.DefaultEnv)
}

func newDeleteCommand(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &deleteCommand{env: env})
}

type deleteCommand struct {
	env *commoncli.Env
	// SPIFFE ID of the trust domain bundle
	id string
	// Deletion mode
	mode string
	// Command printer
	printer cliprinter.Printer
}

func (c *deleteCommand) Name() string {
	return "bundle delete"
}

func (c *deleteCommand) Synopsis() string {
	return "Deletes federated bundle data"
}

func (c *deleteCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.id, "id", "", "SPIFFE ID of the trust domain")
	fs.StringVar(&c.mode, "mode", deleteBundleRestrict, fmt.Sprintf("Deletion mode: one of %s, %s, or %s", deleteBundleRestrict, deleteBundleDelete, deleteBundleDissociate))
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, prettyPrintDelete)
}

func (c *deleteCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	if c.id == "" {
		return errors.New("id is required")
	}

	mode, err := deleteModeFromFlag(c.mode)
	if err != nil {
		return err
	}

	bundleClient := serverClient.NewBundleClient()
	resp, err := bundleClient.BatchDeleteFederatedBundle(ctx, &bundlev1.BatchDeleteFederatedBundleRequest{
		Mode: mode,
		TrustDomains: []string{
			c.id,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete federated bundle: %w", err)
	}

	return c.printer.PrintProto(resp)
}

func prettyPrintDelete(env *commoncli.Env, results ...any) error {
	deleteResp, ok := results[0].(*bundlev1.BatchDeleteFederatedBundleResponse)
	if !ok {
		return cliprinter.ErrInternalCustomPrettyFunc
	}
	result := deleteResp.Results[0]
	switch result.Status.Code {
	case int32(codes.OK):
		env.Println("bundle deleted.")
		return nil
	default:
		return fmt.Errorf("failed to delete federated bundle %q: %s", result.TrustDomain, result.Status.Message)
	}
}

func deleteModeFromFlag(mode string) (bundlev1.BatchDeleteFederatedBundleRequest_Mode, error) {
	switch mode {
	case "", deleteBundleRestrict:
		return bundlev1.BatchDeleteFederatedBundleRequest_RESTRICT, nil
	case deleteBundleDissociate:
		return bundlev1.BatchDeleteFederatedBundleRequest_DISSOCIATE, nil
	case deleteBundleDelete:
		return bundlev1.BatchDeleteFederatedBundleRequest_DELETE, nil
	default:
		return bundlev1.BatchDeleteFederatedBundleRequest_RESTRICT, fmt.Errorf("unsupported mode %q", mode)
	}
}
