package token

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/mock/proto/api/registration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
)

var (
	ctx = context.Background()
)

func TestCreateToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c := mock_registration.NewMockRegistrationClient(ctrl)
	req := &registration.JoinToken{Ttl: 60}
	resp := &registration.JoinToken{Token: "foobar", Ttl: 60}

	c.EXPECT().CreateJoinToken(gomock.Any(), req).Return(resp, nil)
	token, err := GenerateCLI{}.createToken(ctx, c, 60)
	require.NoError(t, err)
	assert.Equal(t, "foobar", token)
}

func TestCreateVanityRecord(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c := mock_registration.NewMockRegistrationClient(ctrl)
	token := "foobar"
	spiffeID := "spiffe://example.org/VanityID"
	tokenID := "spiffe://example.org/spire/agent/join_token/foobar"

	req := &common.RegistrationEntry{
		ParentId: tokenID,
		SpiffeId: spiffeID,
		Selectors: []*common.Selector{
			{Type: "spiffe_id", Value: tokenID},
		},
	}

	c.EXPECT().CreateEntry(gomock.Any(), req)
	err := GenerateCLI{}.createVanityRecord(ctx, c, token, spiffeID)
	assert.NoError(t, err)

	// Test a bad spiffe id
	spiffeID = "badID/foo/bar"
	c.EXPECT().CreateEntry(gomock.Any(), gomock.Any()).MaxTimes(0)
	err = GenerateCLI{}.createVanityRecord(ctx, c, token, spiffeID)
	assert.Error(t, err)
}
