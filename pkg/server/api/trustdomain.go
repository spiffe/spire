package api

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/protoutil"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
)

// ProtoToFederationRelationship convert and validate proto to datastore federated relationship
func ProtoToFederationRelationship(f *types.FederationRelationship) (*datastore.FederationRelationship, error) {
	return ProtoToFederationRelationshipWithMask(f, nil)
}

// ProtoToFederationRelationshipWithMask convert and validate proto to datastore federated relationship, and apply mask
func ProtoToFederationRelationshipWithMask(f *types.FederationRelationship, mask *types.FederationRelationshipMask) (*datastore.FederationRelationship, error) {
	if f == nil {
		return nil, errors.New("missing federation relationship")
	}

	if mask == nil {
		mask = protoutil.AllTrueFederationRelationshipMask
	}

	trustDomain, err := spiffeid.TrustDomainFromString(f.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trust domain: %w", err)
	}

	var bundleEndpointURL *url.URL
	if mask.BundleEndpointUrl {
		bundleEndpointURL, err = url.Parse(f.BundleEndpointUrl)
		switch {
		case err != nil:
			return nil, fmt.Errorf("failed to parse bundle endpoint URL: %w", err)
		case bundleEndpointURL.Scheme != "https":
			return nil, errors.New("bundle endpoint URL must use the https scheme")
		case bundleEndpointURL.Host == "":
			return nil, errors.New("bundle endpoint URL must specify the host")
		case bundleEndpointURL.User != nil:
			return nil, errors.New("bundle endpoint URL must not contain user info")
		}
	}

	resp := &datastore.FederationRelationship{
		TrustDomain:       trustDomain,
		BundleEndpointURL: bundleEndpointURL,
	}

	if mask.BundleEndpointProfile {
		switch profile := f.BundleEndpointProfile.(type) {
		case *types.FederationRelationship_HttpsSpiffe:
			if profile.HttpsSpiffe == nil {
				return nil, errors.New("bundle endpoint profile does not contains \"HttpsSpiffe\"")
			}

			spiffeID, err := spiffeid.FromString(profile.HttpsSpiffe.EndpointSpiffeId)
			if err != nil {
				return nil, fmt.Errorf("failed to parse endpoint SPIFFE ID: %w", err)
			}

			var bundle *common.Bundle
			if profile.HttpsSpiffe.Bundle != nil {
				bundle, err = ProtoToBundle(profile.HttpsSpiffe.Bundle)
				if err != nil {
					return nil, fmt.Errorf("failed to parse bundle: %w", err)
				}
				// Having a bundle present means that this is a self-serving
				// bundle endpoint. We need to ensure that the relationship, and
				// endpoint SPIFFE ID, and the bundle all have matching trust
				// domain names.
				switch {
				case trustDomain.IDString() != bundle.TrustDomainId:
					return nil, fmt.Errorf("self-serving bundle endpoint for %q has a bundle from another trust domain (%q)", trustDomain, profile.HttpsSpiffe.Bundle.TrustDomain)
				case trustDomain != spiffeID.TrustDomain():
					return nil, fmt.Errorf("self-serving bundle endpoint for %q has a SPIFFE ID from another trust domain (%q)", trustDomain, spiffeID.TrustDomain())
				}
			} else if trustDomain == spiffeID.TrustDomain() {
				// No bundle means that this is a relationship with a non
				// self-serving endpoint. The endpoint SPIFFE ID should be
				// from a different trust domain.
				return nil, fmt.Errorf("non self-serving bundle endpoint for %q has a SPIFFE ID from the same trust domain", trustDomain)
			}

			resp.BundleEndpointProfile = datastore.BundleEndpointSPIFFE
			resp.EndpointSPIFFEID = spiffeID
			resp.Bundle = bundle
		case *types.FederationRelationship_HttpsWeb:
			resp.BundleEndpointProfile = datastore.BundleEndpointWeb
		default:
			return nil, fmt.Errorf("unsupported bundle endpoint profile type: %T", f.BundleEndpointProfile)
		}
	}

	return resp, nil
}

// FederationRelationshipToProto converts datastore federation relationship to types proto
func FederationRelationshipToProto(f *datastore.FederationRelationship, mask *types.FederationRelationshipMask) (*types.FederationRelationship, error) {
	if mask == nil {
		mask = protoutil.AllTrueFederationRelationshipMask
	}
	if f.TrustDomain.String() == "" {
		return nil, errors.New("trust domain is required")
	}

	resp := &types.FederationRelationship{
		TrustDomain: f.TrustDomain.String(),
	}

	if mask.BundleEndpointUrl {
		if f.BundleEndpointURL == nil {
			return nil, errors.New("bundle endpoint URL is required")
		}
		resp.BundleEndpointUrl = f.BundleEndpointURL.String()
	}

	if mask.BundleEndpointProfile {
		switch f.BundleEndpointProfile {
		case datastore.BundleEndpointSPIFFE:
			profile := &types.FederationRelationship_HttpsSpiffe{
				HttpsSpiffe: &types.HTTPSSPIFFEProfile{
					EndpointSpiffeId: f.EndpointSPIFFEID.String(),
				},
			}
			// Only self-serving endpoints has a bundle
			if f.EndpointSPIFFEID.TrustDomain() == f.TrustDomain {
				bundle, err := BundleToProto(f.Bundle)
				if err != nil {
					return nil, err
				}
				profile.HttpsSpiffe.Bundle = bundle
			}

			resp.BundleEndpointProfile = profile
		case datastore.BundleEndpointWeb:
			resp.BundleEndpointProfile = &types.FederationRelationship_HttpsWeb{}
		default:
			return nil, fmt.Errorf("unsupported BundleEndpointProfile: %q", f.BundleEndpointProfile)
		}
	}

	return resp, nil
}
