package federation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
)

// FederationRelationship type is used for parsing federation relationships from file
type federationRelationshipJSON struct {
	TrustDomain           string          `json:"trust_domain,omitempty"`
	BundleEndpointURL     string          `json:"bundle_endpoint_url,omitempty"`
	BundleEndpointProfile string          `json:"bundle_endpoint_profile,omitempty"`
	EndpointSPIFFEID      string          `json:"endpoint_spiffe_id,omitempty"`
	Bundle                json.RawMessage `json:"bundle,omitempty"`
	BundleFormat          string          `json:"bundle_format,omitempty"`
	BundlePath            string
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
	if err := json.Unmarshal(dat, &relationships); err != nil {
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

func jsonToProto(fr *federationRelationshipJSON) (*types.FederationRelationship, error) {
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

	switch fr.BundleEndpointProfile {
	case profileHTTPSWeb:
		if fr.EndpointSPIFFEID != "" {
			return nil, errors.New("the 'https_web' endpoint profile does not expect an endpoint SPIFFE ID")
		}
		if fr.BundlePath != "" {
			return nil, errors.New("the 'https_web' endpoint profile does not expect a bundle")
		}
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

		var bundle *types.Bundle
		switch {
		case fr.BundlePath != "":
			bundle, err = bundleFromPath(fr.BundlePath, fr.BundleFormat, endpointSPIFFEID.TrustDomain().String())
			if err != nil {
				return nil, err
			}
		case fr.Bundle != nil:
			bundle, err = bundleFromRawMesssage(fr.Bundle, fr.BundleFormat, endpointSPIFFEID.TrustDomain().String())
			if err != nil {
				return nil, fmt.Errorf("cannot parse bundle raw message: %w", err)
			}
		}

		profile := &types.FederationRelationship_HttpsSpiffe{
			HttpsSpiffe: &types.HTTPSSPIFFEProfile{
				EndpointSpiffeId: endpointSPIFFEID.String(),
				Bundle:           bundle,
			},
		}
		proto.BundleEndpointProfile = profile

	default:
		return nil, fmt.Errorf("unknown bundle endpoint profile type: %q", fr.BundleEndpointProfile)
	}

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

// bundleFromRawMesssage get a bundle for a raw message
func bundleFromRawMesssage(raw json.RawMessage, bundleFormat string, endpointTrustDomain string) (*types.Bundle, error) {
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

func printFederationRelationship(fr *types.FederationRelationship, printf func(format string, args ...interface{}) error) {
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
