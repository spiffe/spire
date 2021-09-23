package federation

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"google.golang.org/grpc/codes"
)

const (
	profileWeb    = "web"
	profileSPIFFE = "spiffe"
)

// NewCreateCommand creates a new "create" subcommand for "federation" command.
func NewCreateCommand() cli.Command {
	return newCreateCommand(common_cli.DefaultEnv)
}

func newCreateCommand(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(createCommand))
}

type createCommand struct {
	path string
	fr   FederationRelationship
}

// FederationRelationship type is used for parsing federation relationships from file
type FederationRelationship struct {
	TrustDomain           string `json:"trust_domain"`
	BundleEndpointURL     string `json:"bundle_endpoint_url"`
	BundleEndpointProfile string `json:"bundle_endpoint_profile"`
	EndpointSPIFFEID      string `json:"endpoint_spiffe_id"`
	BundlePath            string `json:"bundle_path"`
	BundleFormat          string `json:"bundle_format"`
}

// FederationRelationships type is used for parsing federation relationships from file
type FederationRelationships struct {
	FederationRelationships []*FederationRelationship `json:"federation_relationships"`
}

func (*createCommand) Name() string {
	return "federation create"
}

func (*createCommand) Synopsis() string {
	return "Creates a federation relationship to a foreign trust domain"
}

func (c *createCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.path, "data", "", "Path to a file containing federation relationships in JSON format (optional). If set to '-', read the JSON from stdin.")
	f.StringVar(&c.fr.TrustDomain, "trustDomain", "", "The trust domain name (e.g., \"example.org\") to federate with")
	f.StringVar(&c.fr.BundleEndpointURL, "bundleEndpointURL", "", "URL of the SPIFFE bundle endpoint that provides the trust bundle to federate with (must use the HTTPS protocol)")
	f.StringVar(&c.fr.BundleEndpointProfile, "bundleEndpointProfile", "spiffe", fmt.Sprintf("Endpoint profile type. Eithe %q or %q", profileWeb, profileSPIFFE))
	f.StringVar(&c.fr.EndpointSPIFFEID, "endpointSpiffeID", "", "SPIFFE ID of the SPIFFE bundle endpoint server. Only used for 'spiffe' profile.")
	f.StringVar(&c.fr.BundlePath, "bundlePath", "", "Path to the bundle data (optional). Only used for 'spiffe' profile.")
	f.StringVar(&c.fr.BundleFormat, "bundleFormat", util.FormatPEM, fmt.Sprintf("The format of the bundle data (optional). Either %q or %q. Only used for 'spiffe' profile.", util.FormatPEM, util.FormatSPIFFE))
}

func (c *createCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	if err := c.validate(env); err != nil {
		return err
	}

	var err error
	var federationRelationships []*types.FederationRelationship
	if c.path != "" {
		federationRelationships, err = parseFile(c.path)
	} else {
		federationRelationships, err = c.parseConfig()
	}
	if err != nil {
		return err
	}

	succeeded, failed, err := createFederationRelationships(ctx, serverClient.NewTrustDomainClient(), federationRelationships)
	if err != nil {
		return err
	}

	// Print federation relationships that succeeded to be created
	for _, r := range succeeded {
		env.Println()
		printFederationRelationship(r.FederationRelationship, env.Printf)
	}

	// Print federation relationships that failed to be created
	for _, r := range failed {
		env.Println()
		env.ErrPrintf("Failed to create the following federation relationship (code: %s, msg: %q):\n",
			codes.Code(r.Status.Code),
			r.Status.Message)
		printFederationRelationship(r.FederationRelationship, env.ErrPrintf)
	}

	if len(failed) > 0 {
		return errors.New("failed to create one or more federation relationships")
	}

	return nil
}

func (c *createCommand) validate(env *common_cli.Env) error {
	// If a path is set, we have all we need
	if c.path != "" {
		return nil
	}

	if c.fr.TrustDomain == "" {
		return errors.New("trust domain is required")
	}

	if c.fr.BundleEndpointURL == "" {
		return errors.New("bundle endpoint URL is required")
	}

	switch c.fr.BundleEndpointProfile {
	case "spiffe":
		if c.fr.EndpointSPIFFEID == "" {
			return errors.New("endpoint SPIFFE ID is required if 'spiffe' endpoint profile is set")
		}
	case "web":
		if c.fr.EndpointSPIFFEID != "" {
			env.Println("Endpoint SPIFFE ID is ignored for 'web' endpoint profile")
		}
		if c.fr.BundlePath != "" {
			env.Println("Bundle path is ignored for 'web' endpoint profile")
		}
	default:
		return fmt.Errorf("unknown bundle endpoint profile type: %q", c.fr.BundleEndpointProfile)
	}

	return nil
}

func (c *createCommand) parseConfig() ([]*types.FederationRelationship, error) {
	fr, err := cliRelationshipToProtoRelationship(&c.fr)
	if err != nil {
		return nil, err
	}

	return []*types.FederationRelationship{fr}, nil
}

func parseFile(path string) ([]*types.FederationRelationship, error) {
	relationships := &FederationRelationships{}

	r := os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}

	dat, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(dat, &relationships); err != nil {
		return nil, err
	}

	protoRelationships := []*types.FederationRelationship{}
	for i, relationship := range relationships.FederationRelationships {
		protoRelationship, err := cliRelationshipToProtoRelationship(relationship)
		if err != nil {
			return nil, fmt.Errorf("cannot parse item %v: %w", i, err)
		}
		protoRelationships = append(protoRelationships, protoRelationship)
	}
	return protoRelationships, nil
}

func createFederationRelationships(ctx context.Context, c trustdomainv1.TrustDomainClient, federationRelationships []*types.FederationRelationship) (succeeded, failed []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result, err error) {
	resp, err := c.BatchCreateFederationRelationship(ctx, &trustdomainv1.BatchCreateFederationRelationshipRequest{
		FederationRelationships: federationRelationships,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("request failed: %w", err)
	}

	for i, r := range resp.Results {
		switch r.Status.Code {
		case int32(codes.OK):
			succeeded = append(succeeded, r)
		default:
			// The trust domain API does not include in the results the relationships that
			// failed to be created, so we populate them from the request data.
			r.FederationRelationship = federationRelationships[i]
			failed = append(failed, r)
		}
	}

	return succeeded, failed, nil
}

func cliRelationshipToProtoRelationship(cliFR *FederationRelationship) (*types.FederationRelationship, error) {
	fr := &types.FederationRelationship{
		TrustDomain:       cliFR.TrustDomain,
		BundleEndpointUrl: cliFR.BundleEndpointURL,
	}

	switch cliFR.BundleEndpointProfile {
	case profileWeb:
		fr.BundleEndpointProfile = &types.FederationRelationship_HttpsWeb{
			HttpsWeb: &types.HTTPSWebProfile{},
		}
	case profileSPIFFE:
		var bundle *types.Bundle
		if cliFR.BundlePath != "" {
			bundleBytes, err := os.ReadFile(cliFR.BundlePath)
			if err != nil {
				return nil, fmt.Errorf("cannot read bundle file: %w", err)
			}

			endpointSPIFFEID, err := spiffeid.FromString(cliFR.EndpointSPIFFEID)
			if err != nil {
				return nil, fmt.Errorf("cannot parse bundle endpoint SPIFFE ID: %w", err)
			}

			bundle, err = util.ParseBundle(bundleBytes, cliFR.BundleFormat, endpointSPIFFEID.TrustDomain().String())
			if err != nil {
				return nil, fmt.Errorf("cannot parse bundle file: %w", err)
			}
		}

		fr.BundleEndpointProfile = &types.FederationRelationship_HttpsSpiffe{
			HttpsSpiffe: &types.HTTPSSPIFFEProfile{
				EndpointSpiffeId: cliFR.EndpointSPIFFEID,
				Bundle:           bundle,
			},
		}

	default:
		return nil, fmt.Errorf("unknown bundle endpoint profile: %q, please use 'spiffe' or 'web'", cliFR.BundleEndpointProfile)
	}

	return fr, nil
}
