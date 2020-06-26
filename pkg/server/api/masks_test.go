package api

import (
	"testing"

	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/stretchr/testify/assert"
)

func TestAllTrueMasks(t *testing.T) {
	assert.Equal(t, &types.AgentMask{
		AttestationType:      true,
		X509SvidSerialNumber: true,
		X509SvidExpiresAt:    true,
		Selectors:            true,
		Banned:               true,
	}, AllTrueAgentMask)

	assert.Equal(t, &types.BundleMask{
		X509Authorities: true,
		JwtAuthorities:  true,
		RefreshHint:     true,
		SequenceNumber:  true,
	}, AllTrueBundleMask)

	assert.Equal(t, &types.EntryMask{
		SpiffeId:      true,
		ParentId:      true,
		Selectors:     true,
		Ttl:           true,
		FederatesWith: true,
		Admin:         true,
		Downstream:    true,
		ExpiresAt:     true,
		DnsNames:      true,
	}, AllTrueEntryMask)
}
