package token

import (
	"flag"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"

	"golang.org/x/net/context"
)

func NewGenerateCommand() cli.Command {
	return newGenerateCommand(common_cli.DefaultEnv)
}

func newGenerateCommand(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(generateCommand))
}

type generateCommand struct {
	// Optional SPIFFE ID to create with the token
	SpiffeID string

	// Token TTL in seconds
	TTL int
}

func (g *generateCommand) Name() string {
	return "generate"
}

func (g *generateCommand) Synopsis() string {
	return "Generates a join token"
}

func (g *generateCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
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

	if err := env.Printf("Token: %s\n", resp.Value); err != nil {
		return err
	}

	if g.SpiffeID == "" {
		env.Printf("Warning: Missing SPIFFE ID.\n")
		return nil
	}

	return nil
}

func getID(spiffeID string) (*types.SPIFFEID, error) {
	if spiffeID == "" {
		return nil, nil
	}

	id, err := spiffeid.FromString(spiffeID)
	if err != nil {
		return nil, err
	}
	return &types.SPIFFEID{
		TrustDomain: id.TrustDomain().String(),
		Path:        id.Path(),
	}, nil
}

func (g *generateCommand) AppendFlags(fs *flag.FlagSet) {
	fs.IntVar(&g.TTL, "ttl", 600, "Token TTL in seconds")
	fs.StringVar(&g.SpiffeID, "spiffeID", "", "Additional SPIFFE ID to assign the token owner (optional)")
}
