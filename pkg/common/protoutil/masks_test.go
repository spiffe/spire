package protoutil_test

import (
	"testing"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/protoutil"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/assert"
)

func TestAllTrueMasks(t *testing.T) {
	assert.Equal(t, &types.AgentMask{
		AttestationType:      true,
		X509SvidSerialNumber: true,
		X509SvidExpiresAt:    true,
		Selectors:            true,
		Banned:               true,
	}, protoutil.AllTrueAgentMask)

	assert.Equal(t, &types.BundleMask{
		X509Authorities: true,
		JwtAuthorities:  true,
		RefreshHint:     true,
		SequenceNumber:  true,
	}, protoutil.AllTrueBundleMask)

	assert.Equal(t, &types.EntryMask{
		SpiffeId:       true,
		ParentId:       true,
		Selectors:      true,
		Ttl:            true,
		FederatesWith:  true,
		Admin:          true,
		Downstream:     true,
		ExpiresAt:      true,
		DnsNames:       true,
		RevisionNumber: true,
		StoreSvid:      true,
	}, protoutil.AllTrueEntryMask)

	assert.Equal(t, &common.BundleMask{
		RootCas:        true,
		JwtSigningKeys: true,
		RefreshHint:    true,
	}, protoutil.AllTrueCommonBundleMask)

	assert.Equal(t, &common.AttestedNodeMask{
		AttestationDataType: true,
		CertSerialNumber:    true,
		CertNotAfter:        true,
		NewCertSerialNumber: true,
		NewCertNotAfter:     true,
		CanReattest:         true,
	}, protoutil.AllTrueCommonAgentMask)

	assert.Equal(t, &types.FederationRelationshipMask{
		BundleEndpointUrl:     true,
		BundleEndpointProfile: true,
		TrustDomainBundle:     true,
	}, protoutil.AllTrueFederationRelationshipMask)
}
