package cli

import (
	"log"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-server/cli/agent"
	"github.com/spiffe/spire/cmd/spire-server/cli/bundle"
	"github.com/spiffe/spire/cmd/spire-server/cli/entry"
	"github.com/spiffe/spire/cmd/spire-server/cli/healthcheck"
	"github.com/spiffe/spire/cmd/spire-server/cli/jwt"
	"github.com/spiffe/spire/cmd/spire-server/cli/run"
	"github.com/spiffe/spire/cmd/spire-server/cli/token"
	"github.com/spiffe/spire/cmd/spire-server/cli/x509"
	"github.com/spiffe/spire/pkg/common/version"
)

func Run(args []string) int {
	c := cli.NewCLI("spire-server", version.Version())
	c.Args = args
	c.Commands = map[string]cli.CommandFactory{
		"agent evict": func() (cli.Command, error) {
			return &agent.EvictCLI{}, nil
		},
		"agent list": func() (cli.Command, error) {
			return &agent.ListCLI{}, nil
		},
		"agent show": func() (cli.Command, error) {
			return &agent.ShowCLI{}, nil
		},
		"bundle show": func() (cli.Command, error) {
			return bundle.NewShowCommand(), nil
		},
		"bundle list": func() (cli.Command, error) {
			return bundle.NewListCommand(), nil
		},
		"bundle set": func() (cli.Command, error) {
			return bundle.NewSetCommand(), nil
		},
		"bundle delete": func() (cli.Command, error) {
			return bundle.NewDeleteCommand(), nil
		},
		"experimental bundle show": func() (cli.Command, error) {
			return bundle.NewExperimentalShowCommand(), nil
		},
		"experimental bundle list": func() (cli.Command, error) {
			return bundle.NewExperimentalListCommand(), nil
		},
		"experimental bundle set": func() (cli.Command, error) {
			return bundle.NewExperimentalSetCommand(), nil
		},
		"entry create": func() (cli.Command, error) {
			return &entry.CreateCLI{}, nil
		},
		"entry update": func() (cli.Command, error) {
			return &entry.UpdateCLI{}, nil
		},
		"entry delete": func() (cli.Command, error) {
			return &entry.DeleteCLI{}, nil
		},
		"entry show": func() (cli.Command, error) {
			return &entry.ShowCLI{}, nil
		},
		"run": func() (cli.Command, error) {
			return &run.RunCLI{}, nil
		},
		"token generate": func() (cli.Command, error) {
			return &token.GenerateCLI{}, nil
		},
		"healthcheck": func() (cli.Command, error) {
			return healthcheck.NewHealthCheckCommand(), nil
		},
		"x509 mint": func() (cli.Command, error) {
			return x509.NewMintCommand(), nil
		},
		"jwt mint": func() (cli.Command, error) {
			return jwt.NewMintCommand(), nil
		},
	}

	exitStatus, err := c.Run()
	if err != nil {
		log.Println(err)
	}
	return exitStatus
}
