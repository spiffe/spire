package federation

import (
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

func printFederationRelationship(fr *types.FederationRelationship, printf func(format string, args ...interface{}) error) {
	_ = printf("Trust domain              : %s\n", fr.TrustDomain)
	_ = printf("Bundle endpoint URL       : %s\n", fr.BundleEndpointUrl)

	switch profile := fr.BundleEndpointProfile.(type) {
	case *types.FederationRelationship_HttpsWeb:
		_ = printf("Bundle endpoint profile   : %s\n", "https_web")

	case *types.FederationRelationship_HttpsSpiffe:
		_ = printf("Bundle endpoint profile   : %s\n", "https_spiffe")
		_ = printf("Endpoint SPIFFE ID        : %s\n", profile.HttpsSpiffe.EndpointSpiffeId)

		if profile.HttpsSpiffe.Bundle != nil {
			_ = printf("Bundle trust domain       : %s\n", profile.HttpsSpiffe.Bundle.TrustDomain)
		}
	}
}
