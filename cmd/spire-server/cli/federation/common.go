package federation

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
)

// FederationRelationships type is used for parsing federation relationships from file
type federationRelationships struct {
	FederationRelationships []*federationRelationshipConfig `json:"federationRelationships"`
}

// federationRelationshipConfig is the configuration for the federation relationship provided either by CLI flags or a JSON file.
type federationRelationshipConfig struct {
	TrustDomain             string          `json:"trustDomain,omitempty"`
	BundleEndpointURL       string          `json:"bundleEndpointURL,omitempty"`
	BundleEndpointProfile   string          `json:"bundleEndpointProfile,omitempty"`
	EndpointSPIFFEID        string          `json:"endpointSPIFFEID,omitempty"`
	TrustDomainBundle       json.RawMessage `json:"trustDomainBundle,omitempty"`
	TrustDomainBundleFormat string          `json:"trustDomainBundleFormat,omitempty"`
	// TrustDomainBundlePath is the path to the bundle on disk. It is only set via CLI flags. JSON config uses the embedded `Bundle` field instead.
	TrustDomainBundlePath string `json:"-"`
}

func (c federationRelationshipConfig) isEmpty() bool {
	return c.BundleEndpointProfile == "" &&
		c.BundleEndpointURL == "" &&
		c.TrustDomainBundleFormat == util.FormatPEM &&
		c.TrustDomainBundlePath == "" &&
		c.EndpointSPIFFEID == "" &&
		c.TrustDomain == ""
}

// federationRelationshipsFromFile parse a json file into types FederationRelationships
func federationRelationshipsFromFile(path string) ([]*types.FederationRelationship, error) {
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

	relationships := &federationRelationships{}
	if err := json.Unmarshal(dat, relationships); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	protoRelationships := []*types.FederationRelationship{}
	for i, relationship := range relationships.FederationRelationships {
		protoRelationship, err := jsonToProto(relationship)
		if err != nil {
			return nil, fmt.Errorf("could not parse item %d: %w", i, err)
		}
		protoRelationships = append(protoRelationships, protoRelationship)
	}

	return protoRelationships, nil
}

func jsonToProto(fr *federationRelationshipConfig) (*types.FederationRelationship, error) {
	if fr.TrustDomain == "" {
		return nil, errors.New("trust domain is required")
	}

	if fr.BundleEndpointURL == "" {
		return nil, errors.New("bundle endpoint URL is required")
	}

	proto := &types.FederationRelationship{
		TrustDomain:       fr.TrustDomain,
		BundleEndpointUrl: fr.BundleEndpointURL,
	}

	bundleTrustDomain := fr.TrustDomain

	switch fr.BundleEndpointProfile {
	case profileHTTPSWeb:
		proto.BundleEndpointProfile = &types.FederationRelationship_HttpsWeb{
			HttpsWeb: &types.HTTPSWebProfile{},
		}

	case profileHTTPSSPIFFE:
		if fr.EndpointSPIFFEID == "" {
			return nil, errors.New("endpoint SPIFFE ID is required if 'https_spiffe' endpoint profile is set")
		}
		endpointSPIFFEID, err := spiffeid.FromString(fr.EndpointSPIFFEID)
		if err != nil {
			return nil, fmt.Errorf("cannot parse bundle endpoint SPIFFE ID: %w", err)
		}
		bundleTrustDomain = endpointSPIFFEID.TrustDomain().Name()

		proto.BundleEndpointProfile = &types.FederationRelationship_HttpsSpiffe{
			HttpsSpiffe: &types.HTTPSSPIFFEProfile{
				EndpointSpiffeId: fr.EndpointSPIFFEID,
			},
		}

	default:
		return nil, fmt.Errorf("unknown bundle endpoint profile type: %q", fr.BundleEndpointProfile)
	}

	var bundle *types.Bundle
	switch {
	case fr.TrustDomainBundlePath != "":
		b, err := bundleFromPath(fr.TrustDomainBundlePath, fr.TrustDomainBundleFormat, bundleTrustDomain)
		if err != nil {
			return nil, err
		}
		bundle = b
	case fr.TrustDomainBundle != nil:
		b, err := bundleFromRawMessage(fr.TrustDomainBundle, fr.TrustDomainBundleFormat, bundleTrustDomain)
		if err != nil {
			return nil, fmt.Errorf("cannot parse bundle raw message: %w", err)
		}
		bundle = b
	}
	proto.TrustDomainBundle = bundle

	return proto, nil
}

// bundleFromPath get a bundle from a file
func bundleFromPath(bundlePath string, bundleFormat string, endpointTrustDomain string) (*types.Bundle, error) {
	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("cannot read bundle file: %w", err)
	}

	bundle, err := util.ParseBundle(bundleBytes, bundleFormat, endpointTrustDomain)
	if err != nil {
		return nil, fmt.Errorf("cannot parse bundle file: %w", err)
	}

	return bundle, nil
}

// bundleFromRawMessage get a bundle for a raw message
func bundleFromRawMessage(raw json.RawMessage, bundleFormat string, endpointTrustDomain string) (*types.Bundle, error) {
	var bundle []byte

	switch bundleFormat {
	case util.FormatPEM:
		var pem string
		if err := json.Unmarshal(raw, &pem); err != nil {
			return nil, fmt.Errorf("failed to unmarshal json: %w", err)
		}
		bundle = []byte(pem)

	case util.FormatSPIFFE:
		bundle = raw
	default:
		return nil, fmt.Errorf("bundle format %q is unsupported", bundleFormat)
	}
	return util.ParseBundle(bundle, bundleFormat, endpointTrustDomain)
}

func printFederationRelationship(fr *types.FederationRelationship, printf func(format string, args ...any) error) {
	_ = printf("Trust domain              : %s\n", fr.TrustDomain)
	_ = printf("Bundle endpoint URL       : %s\n", fr.BundleEndpointUrl)

	switch profile := fr.BundleEndpointProfile.(type) {
	case *types.FederationRelationship_HttpsWeb:
		_ = printf("Bundle endpoint profile   : %s\n", "https_web")

	case *types.FederationRelationship_HttpsSpiffe:
		_ = printf("Bundle endpoint profile   : %s\n", "https_spiffe")
		_ = printf("Endpoint SPIFFE ID        : %s\n", profile.HttpsSpiffe.EndpointSpiffeId)
	}
}

func appendConfigFlags(config *federationRelationshipConfig, f *flag.FlagSet) {
	f.StringVar(&config.TrustDomain, "trustDomain", "", `Name of the trust domain to federate with (e.g., example.org)`)
	f.StringVar(&config.BundleEndpointURL, "bundleEndpointURL", "", "URL of the SPIFFE bundle endpoint that provides the trust bundle (must use the HTTPS protocol)")
	f.StringVar(&config.BundleEndpointProfile, "bundleEndpointProfile", "", fmt.Sprintf("Endpoint profile type (either %q or %q)", profileHTTPSWeb, profileHTTPSSPIFFE))
	f.StringVar(&config.EndpointSPIFFEID, "endpointSpiffeID", "", "SPIFFE ID of the SPIFFE bundle endpoint server. Only used for 'spiffe' profile.")
	f.StringVar(&config.TrustDomainBundlePath, "trustDomainBundlePath", "", "Path to the trust domain bundle data (optional).")
	f.StringVar(&config.TrustDomainBundleFormat, "trustDomainBundleFormat", util.FormatPEM, fmt.Sprintf("The format of the bundle data (optional). Either %q or %q.", util.FormatPEM, util.FormatSPIFFE))
}

func getRelationships(config *federationRelationshipConfig, path string) ([]*types.FederationRelationship, error) {
	if path != "" {
		if !config.isEmpty() {
			return nil, errors.New("cannot use other flags to specify relationship fields when 'data' flag is set")
		}
		relationships, err := federationRelationshipsFromFile(path)
		if err != nil {
			return nil, err
		}
		return relationships, nil
	}

	proto, err := jsonToProto(config)
	if err != nil {
		return nil, err
	}
	return []*types.FederationRelationship{proto}, nil
}
