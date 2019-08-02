package jwt

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"gopkg.in/square/go-jose.v2/jwt"
)

func NewMintCommand() cli.Command {
	return newMintCommand(common_cli.DefaultEnv)
}

func newMintCommand(env *common_cli.Env) *mintCommand {
	return &mintCommand{
		env: env,
	}
}

type mintCommand struct {
	env *common_cli.Env

	socketPath string
	spiffeID   string
	ttl        time.Duration
	audience   common_cli.StringsFlag
	write      string
}

func (c *mintCommand) Help() string {
	c.parseFlags([]string{"-h"})
	return ""
}

func (c *mintCommand) Synopsis() string {
	return "Mints a JWT-SVID"
}

func (c *mintCommand) Run(args []string) int {
	if err := c.parseFlags(args); err != nil {
		return 1
	}
	if err := c.run(args); err != nil {
		c.env.ErrPrintf("error: %v\n", err)
		return 1
	}
	return 0
}

func (c *mintCommand) parseFlags(args []string) error {
	fs := flag.NewFlagSet("jwt mint", flag.ContinueOnError)
	fs.SetOutput(c.env.Stderr)
	fs.StringVar(&c.socketPath, "registrationUDSPath", util.DefaultSocketPath, "Registration API UDS path")
	fs.StringVar(&c.spiffeID, "spiffeID", "", "SPIFFE ID of the JWT-SVID")
	fs.DurationVar(&c.ttl, "ttl", 0, "TTL of the JWT-SVID")
	fs.Var(&c.audience, "audience", "Audience claim that will be included in the SVID. Can be used more than once.")
	fs.StringVar(&c.write, "write", "", "File to write token to instead of stdout")
	return fs.Parse(args)
}

func (c *mintCommand) run(args []string) error {
	if c.spiffeID == "" {
		return errors.New("spiffeID must be specified")
	}
	if len(c.audience) == 0 {
		return errors.New("at least one audience must be specified")
	}

	client, err := util.NewRegistrationClient(c.env.JoinPath(c.socketPath))
	if err != nil {
		return errors.New("cannot create registration client")
	}

	resp, err := client.MintJWTSVID(context.Background(), &registration.MintJWTSVIDRequest{
		SpiffeId: c.spiffeID,
		Ttl:      ttlToSeconds(c.ttl),
		Audience: c.audience,
	})
	if err != nil {
		return fmt.Errorf("unable to mint SVID: %v", err)
	}

	if resp.Token == "" {
		return errors.New("server response missing token")
	}

	if eol, err := getJWTSVIDEndOfLife(resp.Token); err != nil {
		c.env.ErrPrintf("Unable to determine JWT-SVID lifetime: %v\n", err)
	} else if eol.Sub(time.Now()) < c.ttl {
		c.env.ErrPrintf("JWT-SVID lifetime was capped shorter than specified ttl; expires %q\n", eol.UTC().Format(time.RFC3339))
	}

	if c.write == "" {
		if err := c.env.Println(resp.Token); err != nil {
			return err
		}
	} else {
		tokenPath := c.env.JoinPath(c.write)
		if err := ioutil.WriteFile(tokenPath, []byte(resp.Token), 0600); err != nil {
			return fmt.Errorf("unable to write token: %v", err)
		}
		if err := c.env.Printf("JWT-SVID written to %s\n", tokenPath); err != nil {
			return err
		}
	}

	return nil
}

func getJWTSVIDEndOfLife(token string) (time.Time, error) {
	t, err := jwt.ParseSigned(token)
	if err != nil {
		return time.Time{}, err
	}

	claims := new(jwt.Claims)
	if err := t.UnsafeClaimsWithoutVerification(claims); err != nil {
		return time.Time{}, err
	}

	if claims.Expiry == nil {
		return time.Time{}, errors.New("no expiry claim")
	}

	return claims.Expiry.Time(), nil
}

// ttlToSeconds returns the number of seconds in a duration, rounded up to
// the nearest second
func ttlToSeconds(ttl time.Duration) int32 {
	return int32((ttl + time.Second - 1) / time.Second)
}
