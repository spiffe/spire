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
	profileHTTPSWeb    = "https_web"
	profileHTTPSSPIFFE = "https_spiffe"
)

// NewCreateCommand creates a new "create" subcommand for "federation" command.
func NewCreateCommand() cli.Command {
	return newCreateCommand(common_cli.DefaultEnv)
}

func newCreateCommand(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(createCommand))
}

// FederationRelationship type is used for parsing federation relationships from file
type federationRelationship struct {
	TrustDomain           string `json:"trust_domain"`
	BundleEndpointURL     string `json:"bundle_endpoint_url"`
	BundleEndpointProfile string `json:"bundle_endpoint_profile"`
	EndpointSPIFFEID      string `json:"endpoint_spiffe_id"`
	BundlePath            string `json:"bundle_path"`
	BundleFormat          string `json:"bundle_format"`
}

// FederationRelationships type is used for parsing federation relationships from file
type federationRelationships struct {
	FederationRelationships []*federationRelationship `json:"federation_relationships"`
}

type createCommand struct {
	path string
	fr   federationRelationship
}

func (*createCommand) Name() string {
	return "federation create"
}

func (*createCommand) Synopsis() string {
	return "Creates a federation relationship to a foreign trust domain"
}

func (c *createCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.path, "data", "", "Path to a file containing federation relationships in JSON format (optional). If set to '-', read the JSON from stdin.")
	f.StringVar(&c.fr.TrustDomain, "trustDomain", "", `Name of the trust domain to federate with (e.g., example.org)`)
	f.StringVar(&c.fr.BundleEndpointURL, "bundleEndpointURL", "", "URL of the SPIFFE bundle endpoint that provides the trust bundle (must use the HTTPS protocol)")
	f.StringVar(&c.fr.BundleEndpointProfile, "bundleEndpointProfile", profileHTTPSSPIFFE, fmt.Sprintf("Endpoint profile type (either %q or %q)", profileHTTPSWeb, profileHTTPSSPIFFE))
	f.StringVar(&c.fr.EndpointSPIFFEID, "endpointSpiffeID", "", "SPIFFE ID of the SPIFFE bundle endpoint server. Only used for 'spiffe' profile.")
	f.StringVar(&c.fr.BundlePath, "bundlePath", "", "Path to the bundle data (optional). Only used for 'spiffe' profile.")
	f.StringVar(&c.fr.BundleFormat, "bundleFormat", util.FormatPEM, fmt.Sprintf("The format of the bundle data (optional). Either %q or %q. Only used for 'spiffe' profile.", util.FormatPEM, util.FormatSPIFFE))
}

func (c *createCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
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

func (c *createCommand) parseConfig() ([]*types.FederationRelationship, error) {
	fr, err := cliRelationshipToProtoRelationship(&c.fr)
	if err != nil {
		return nil, err
	}

	return []*types.FederationRelationship{fr}, nil
}

func parseFile(path string) ([]*types.FederationRelationship, error) {
	relationships := &federationRelationships{}

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

func cliRelationshipToProtoRelationship(cliFR *federationRelationship) (*types.FederationRelationship, error) {
	if cliFR.TrustDomain == "" {
		return nil, errors.New("trust domain is required")
	}
	trustDomain, err := spiffeid.TrustDomainFromString(cliFR.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("cannot parse trust domain: %w", err)
	}

	if cliFR.BundleEndpointURL == "" {
		return nil, errors.New("bundle endpoint URL is required")
	}

	fr := &types.FederationRelationship{
		TrustDomain:       trustDomain.String(),
		BundleEndpointUrl: cliFR.BundleEndpointURL,
	}

	switch cliFR.BundleEndpointProfile {
	case profileHTTPSWeb:
		if cliFR.EndpointSPIFFEID != "" {
			return nil, errors.New("the 'https_web' endpoint profile does not expect an endpoint SPIFFE ID")
		}
		if cliFR.BundlePath != "" {
			return nil, errors.New("the 'https_web' endpoint profile does not expect a bundle")
		}
		fr.BundleEndpointProfile = &types.FederationRelationship_HttpsWeb{
			HttpsWeb: &types.HTTPSWebProfile{},
		}
	case profileHTTPSSPIFFE:
		if cliFR.EndpointSPIFFEID == "" {
			return nil, errors.New("endpoint SPIFFE ID is required if 'https_spiffe' endpoint profile is set")
		}
		endpointSPIFFEID, err := spiffeid.FromString(cliFR.EndpointSPIFFEID)
		if err != nil {
			return nil, fmt.Errorf("cannot parse bundle endpoint SPIFFE ID: %w", err)
		}

		switch {
		case cliFR.BundlePath == "" && endpointSPIFFEID.TrustDomain().Compare(trustDomain) == 0:
			return nil, errors.New("bundle is required for self-serving endpoint")
		case cliFR.BundlePath != "" && endpointSPIFFEID.TrustDomain().Compare(trustDomain) != 0:
			return nil, errors.New("bundle should only be present for a self-serving endpoint")
		}

		var bundle *types.Bundle
		if cliFR.BundlePath != "" {
			bundleBytes, err := os.ReadFile(cliFR.BundlePath)
			if err != nil {
				return nil, fmt.Errorf("cannot read bundle file: %w", err)
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
		return nil, fmt.Errorf("unknown bundle endpoint profile type: %q", cliFR.BundleEndpointProfile)
	}

	return fr, nil
}
