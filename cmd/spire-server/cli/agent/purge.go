package agent

import (
	"flag"
	"fmt"
	"time"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"github.com/spiffe/spire/pkg/common/idutil"
	"golang.org/x/net/context"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type purgeCommand struct {
	env           *commoncli.Env
	expiredBefore string
	dryRun        bool
	printer       cliprinter.Printer
}

func NewPurgeCommand() cli.Command {
	return NewPurgeCommandWithEnv(commoncli.DefaultEnv)
}

func NewPurgeCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &purgeCommand{env: env})
}

func (*purgeCommand) Name() string {
	return "agent purge"
}

func (*purgeCommand) Synopsis() string {
	return "Delete expired agents that attested using a non-TOFU security model based on a given time"
}

func (c *purgeCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) (err error) {
	expiredBefore, err := c.parseExpiredBefore()
	if err != nil {
		return err
	}

	agentClient := serverClient.NewAgentClient()
	resp, err := agentClient.ListAgents(ctx, &agentv1.ListAgentsRequest{
		Filter:     &agentv1.ListAgentsRequest_Filter{ByCanReattest: wrapperspb.Bool(true)},
		OutputMask: &types.AgentMask{X509SvidExpiresAt: true},
	})
	if err != nil {
		return fmt.Errorf("failed to list agents: %w", err)
	}

	agents := resp.GetAgents()
	expiredAgents := &expiredAgents{Agents: []*expiredAgent{}}

	for _, agent := range agents {
		id, err := idutil.IDFromProto(agent.Id)
		if err != nil {
			return err
		}

		expirationTime := time.Unix(agent.X509SvidExpiresAt, 0)

		if expirationTime.Before(expiredBefore) {
			result := &expiredAgent{AgentID: id}

			if !c.dryRun {
				if _, err := agentClient.DeleteAgent(ctx, &agentv1.DeleteAgentRequest{Id: agent.Id}); err != nil {
					result.Error = err.Error()
				} else {
					result.Deleted = true
				}
			}
			expiredAgents.Agents = append(expiredAgents.Agents, result)
		}
	}

	return c.printer.PrintStruct(expiredAgents)
}

func (c *purgeCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.expiredBefore, "expiredBefore", "", "Specifies the date before which all expired agents should be deleted. The value should be a date time string in the RFC3339 format. Any agents that expired before this date will be deleted.")
	fs.BoolVar(&c.dryRun, "dryRun", false, "Indicates that the command will not perform any action, but will print the agents that would be purged.")

	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, c.prettyPrintPurgeResult)
}

type expiredAgents struct {
	Agents []*expiredAgent `json:"expired_agents"`
}

type expiredAgent struct {
	AgentID spiffeid.ID `json:"agent_id"`
	Deleted bool        `json:"deleted"`
	Error   string      `json:"error,omitempty"`
}

func (c *purgeCommand) prettyPrintPurgeResult(env *commoncli.Env, results ...interface{}) error {
	if expAgents, ok := results[0].([]interface{})[0].(*expiredAgents); ok {
		if len(expAgents.Agents) == 0 {
			env.Println("No agents to purge.")
			return nil
		}

		msg := fmt.Sprintf("Found %d expired ", len(expAgents.Agents))
		msg = util.Pluralizer(msg, "agent", "agents", len(expAgents.Agents))
		env.Printf("%s\n\n", msg)

		if c.dryRun {
			env.Println("\nAgents that can be purged:")
			for _, result := range expAgents.Agents {
				env.Printf("SPIFFE ID         : %s\n", result.AgentID.String())
			}
			return nil
		}

		var agentsNotPurged []*expiredAgent
		var agentsPurged []*expiredAgent

		for _, result := range expAgents.Agents {
			if result.Deleted {
				agentsPurged = append(agentsPurged, result)
			} else {
				agentsNotPurged = append(agentsNotPurged, result)
			}
		}

		if len(agentsPurged) > 0 {
			c.printAgentsPurged(agentsPurged)
		}

		if len(agentsNotPurged) > 0 {
			c.printAgentsNotPurged(agentsNotPurged)
		}

		return nil
	}
	return cliprinter.ErrInternalCustomPrettyFunc
}

func (c *purgeCommand) printAgentsNotPurged(agentsNotPurged []*expiredAgent) {
	c.env.Println("Agents not purged:")
	for _, result := range agentsNotPurged {
		c.env.Printf("SPIFFE ID         : %s\n", result.AgentID.String())
		if result.Error != "" {
			c.env.Printf("Error             : %s\n", result.Error)
		}
	}
}

func (c *purgeCommand) printAgentsPurged(agentsPurged []*expiredAgent) {
	c.env.Println("Agents purged:")
	for _, result := range agentsPurged {
		c.env.Printf("SPIFFE ID         : %s\n", result.AgentID.String())
	}
}

func (c *purgeCommand) parseExpiredBefore() (expiredBefore time.Time, err error) {
	now := time.Now()
	if c.expiredBefore == "" {
		expiredBefore = now
		return
	}
	expiredBefore, err = time.Parse(time.RFC3339, c.expiredBefore)
	if err != nil {
		err = fmt.Errorf("failed to parse expiredBefore flag: %w", err)
	}
	if expiredBefore.After(now) {
		err = fmt.Errorf("expiredBefore cannot be in the future")
	}
	return
}
