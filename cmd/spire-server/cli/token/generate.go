package token

import (
	"flag"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	prototypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"

	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"

	"golang.org/x/net/context"
)

func NewGenerateCommand() cli.Command {
	return newGenerateCommand(commoncli.DefaultEnv)
}

func newGenerateCommand(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &generateCommand{env: env})
}

type generateCommand struct {
	// Optional SPIFFE ID to create with the token
	SpiffeID string

	// Token TTL in seconds
	TTL     int
	env     *commoncli.Env
	printer cliprinter.Printer
}

func (g *generateCommand) Name() string {
	return "generate"
}

func (g *generateCommand) Synopsis() string {
	return "Generates a join token"
}

func (g *generateCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	id, err := getID(g.SpiffeID)
	if err != nil {
		return err
	}

	c := serverClient.NewAgentClient()
	resp, err := c.CreateJoinToken(ctx, &agentv1.CreateJoinTokenRequest{
		AgentId: id,
		Ttl:     int32(g.TTL),
	})
	if err != nil {
		return err
	}
	return g.printer.PrintProto(resp)
}

func getID(spiffeID string) (*prototypes.SPIFFEID, error) {
	if spiffeID == "" {
		return nil, nil
	}

	id, err := spiffeid.FromString(spiffeID)
	if err != nil {
		return nil, err
	}
	return &prototypes.SPIFFEID{
		TrustDomain: id.TrustDomain().Name(),
		Path:        id.Path(),
	}, nil
}

func (g *generateCommand) AppendFlags(fs *flag.FlagSet) {
	fs.IntVar(&g.TTL, "ttl", 600, "Token TTL in seconds")
	fs.StringVar(&g.SpiffeID, "spiffeID", "", "Additional SPIFFE ID to assign the token owner (optional)")
	cliprinter.AppendFlagWithCustomPretty(&g.printer, fs, g.env, g.prettyPrintGenerate)
}

func (g *generateCommand) prettyPrintGenerate(env *commoncli.Env, results ...interface{}) error {
	generateResp, ok := results[0].(*prototypes.JoinToken)
	if !ok {
		return cliprinter.ErrInternalCustomPrettyFunc
	}

	if err := env.Printf("Token: %s\n", generateResp.Value); err != nil {
		return err
	}

	if g.SpiffeID == "" {
		env.Printf("Warning: Missing SPIFFE ID.\n")
		return nil
	}

	return nil
}
