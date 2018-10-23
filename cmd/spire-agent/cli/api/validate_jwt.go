package api

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/proto/api/workload"

	"github.com/golang/protobuf/jsonpb"
)

func NewValidateJWTCommand() cli.Command {
	return newValidateJWTCommand(defaultEnv, newWorkloadClient)
}

func newValidateJWTCommand(env *env, clientMaker workloadClientMaker) cli.Command {
	return adaptCommand(env, clientMaker, new(validateJWTCommand))
}

type validateJWTCommand struct {
	audience stringsFlag
	svid     string
}

func (*validateJWTCommand) name() string {
	return "validate jwt"
}

func (*validateJWTCommand) synopsis() string {
	return "Validates a JWT SVID"
}

func (c *validateJWTCommand) appendFlags(fs *flag.FlagSet) {
	fs.Var(&c.audience, "audience", "comma separated list of audience values")
	fs.StringVar(&c.svid, "svid", "", "JWT SVID")
}

func (c *validateJWTCommand) run(ctx context.Context, env *env, client *workloadClient) error {
	if len(c.audience) == 0 {
		return errors.New("audience must be specified")
	}
	if len(c.svid) == 0 {
		return errors.New("svid must be specified")
	}

	resp, err := c.validateJWTSVID(ctx, client)
	if err != nil {
		return fmt.Errorf("unable to validate JWT SVID: %v", err)
	}

	env.Println("SVID is valid.")
	env.Println("SPIFFE ID :", resp.SpiffeId)
	claims, err := (&jsonpb.Marshaler{}).MarshalToString(resp.Claims)
	if err != nil {
		return fmt.Errorf("unable to unmarshal claims: %v", err)
	}
	env.Println("Claims    :", claims)

	return nil
}

func (c *validateJWTCommand) validateJWTSVID(ctx context.Context, client *workloadClient) (*workload.ValidateJWTASVIDResponse, error) {
	ctx, cancel := client.prepareContext(ctx)
	defer cancel()
	return client.ValidateJWTASVID(ctx, &workload.ValidateJWTASVIDRequest{
		Audience: c.audience,
		Svid:     c.svid,
	})
}
