package api

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

func NewValidateJWTCommand() cli.Command {
	return newValidateJWTCommand(commoncli.DefaultEnv, newWorkloadClient)
}

func newValidateJWTCommand(env *commoncli.Env, clientMaker workloadClientMaker) cli.Command {
	return adaptCommand(env, clientMaker, &validateJWTCommand{env: env})
}

type validateJWTCommand struct {
	audience string
	svid     string
	env      *commoncli.Env
	printer  cliprinter.Printer
}

func (*validateJWTCommand) name() string {
	return "validate jwt"
}

func (*validateJWTCommand) synopsis() string {
	return "Validates a JWT SVID"
}

func (c *validateJWTCommand) appendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.audience, "audience", "", "expected audience value")
	fs.StringVar(&c.svid, "svid", "", "JWT SVID")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, prettyPrintValidate)
}

func (c *validateJWTCommand) run(ctx context.Context, _ *commoncli.Env, client *workloadClient) error {
	if c.audience == "" {
		return errors.New("audience must be specified")
	}
	if len(c.svid) == 0 {
		return errors.New("svid must be specified")
	}

	resp, err := c.validateJWTSVID(ctx, client)
	if err != nil {
		return err
	}

	return c.printer.PrintProto(resp)
}

func (c *validateJWTCommand) validateJWTSVID(ctx context.Context, client *workloadClient) (*workload.ValidateJWTSVIDResponse, error) {
	ctx, cancel := client.prepareContext(ctx)
	defer cancel()
	resp, err := client.ValidateJWTSVID(ctx, &workload.ValidateJWTSVIDRequest{
		Audience: c.audience,
		Svid:     c.svid,
	})
	if err != nil {
		if s := status.Convert(err); s.Code() == codes.InvalidArgument {
			return nil, fmt.Errorf("SVID is not valid: %v", s.Message())
		}
		return nil, fmt.Errorf("unable to validate JWT SVID: %w", err)
	}
	return resp, nil
}

func prettyPrintValidate(env *commoncli.Env, results ...interface{}) error {
	resp, ok := results[0].(*workload.ValidateJWTSVIDResponse)
	if !ok {
		return cliprinter.ErrInternalCustomPrettyFunc
	}
	if err := env.Println("SVID is valid."); err != nil {
		return err
	}
	if err := env.Println("SPIFFE ID :", resp.SpiffeId); err != nil {
		return err
	}
	claims, err := protojson.Marshal(resp.Claims)
	if err != nil {
		return fmt.Errorf("unable to unmarshal claims: %w", err)
	}
	return env.Println("Claims    :", string(claims))
}
