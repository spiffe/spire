package rotationutil

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShouldRotateX509(t *testing.T) {
	mockClk := clock.NewMock(t)

	for _, tc := range []struct {
		desc               string
		makeCertTemplate   func() (*x509.Certificate, error)
		availabilityTarget time.Duration
		shouldRotate       bool
	}{
		{
			desc: "brand new cert",
			makeCertTemplate: func() (*x509.Certificate, error) {
				return util.NewSVIDTemplate(mockClk, "spiffe://example.org/test")
			},
			shouldRotate: false,
		},
		{
			desc: "cert that's almost expired",
			makeCertTemplate: func() (*x509.Certificate, error) {
				temp, err := util.NewSVIDTemplate(mockClk, "spiffe://example.org/test")
				if err != nil {
					return nil, err
				}
				temp.NotBefore = mockClk.Now().Add(-1 * time.Hour)
				temp.NotAfter = mockClk.Now().Add(1 * time.Minute)
				return temp, nil
			},
			shouldRotate: true,
		},
		{
			desc: "cert that's already expired",
			makeCertTemplate: func() (*x509.Certificate, error) {
				temp, err := util.NewSVIDTemplate(mockClk, "spiffe://example.org/test")
				if err != nil {
					return nil, err
				}
				temp.NotBefore = mockClk.Now().Add(-1 * time.Hour)
				temp.NotAfter = mockClk.Now().Add(-11 * time.Minute)
				return temp, nil
			},
			shouldRotate: true,
		},
		{
			desc: "rotation by availability_target",
			makeCertTemplate: func() (*x509.Certificate, error) {
				temp, err := util.NewSVIDTemplate(mockClk, "spiffe://example.org/test")
				if err != nil {
					return nil, err
				}
				temp.NotBefore = mockClk.Now().Add(-24 * time.Hour)
				temp.NotAfter = mockClk.Now().Add(48 * time.Hour)
				return temp, nil
			},
			availabilityTarget: 48 * time.Hour,
			shouldRotate:       true,
		},
		{
			desc: "x509_svid_ttl isn't long enough to guarantee the availability_target",
			makeCertTemplate: func() (*x509.Certificate, error) {
				temp, err := util.NewSVIDTemplate(mockClk, "spiffe://example.org/test")
				if err != nil {
					return nil, err
				}
				temp.NotBefore = mockClk.Now().Add(-6 * time.Hour)
				temp.NotAfter = mockClk.Now().Add(24 * time.Hour)
				return temp, nil
			},
			availabilityTarget: 24 * time.Hour,
			shouldRotate:       false,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			cert, err := tc.makeCertTemplate()
			require.NoError(t, err)

			rs := NewRotationStrategy(tc.availabilityTarget)
			actual := rs.ShouldRotateX509(mockClk.Now(), cert)
			assert.Equal(t, tc.shouldRotate, actual)
		})
	}
}

func TestX509Expired(t *testing.T) {
	// Cert that's valid for 1hr
	mockClk := clock.NewMock(t)
	temp, err := util.NewSVIDTemplate(mockClk, "spiffe://example.org/test")
	require.NoError(t, err)
	goodCert, _, err := util.SelfSign(temp)
	require.NoError(t, err)

	// Cert is brand new
	assert.False(t, X509Expired(mockClk.Now(), goodCert))

	// Cert that's almost expired
	temp.NotBefore = mockClk.Now().Add(-1 * time.Hour)
	temp.NotAfter = mockClk.Now()
	stillGoodCert, _, err := util.SelfSign(temp)
	require.NoError(t, err)

	assert.False(t, X509Expired(mockClk.Now(), stillGoodCert))

	// Cert that's just expired
	temp.NotBefore = mockClk.Now().Add(-1 * time.Hour)
	temp.NotAfter = mockClk.Now().Add(-1 * time.Nanosecond)
	justBadCert, _, err := util.SelfSign(temp)
	require.NoError(t, err)

	assert.True(t, X509Expired(mockClk.Now(), justBadCert))
}

func TestJWTSVIDExpiresSoon(t *testing.T) {
	// JWT that's valid for 1hr
	mockClk := clock.NewMock(t)

	for _, tc := range []struct {
		desc               string
		token              *client.JWTSVID
		availabilityTarget time.Duration
		shouldRotate       bool
	}{
		{
			desc: "brand new token",
			token: &client.JWTSVID{
				IssuedAt:  mockClk.Now(),
				ExpiresAt: mockClk.Now().Add(time.Hour),
			},
			shouldRotate: false,
		},
		{
			desc: "token that's almost expired",
			token: &client.JWTSVID{
				IssuedAt:  mockClk.Now().Add(-1 * time.Hour),
				ExpiresAt: mockClk.Now().Add(1 * time.Minute),
			},
			shouldRotate: true,
		},
		{
			desc: "token that's already expired",
			token: &client.JWTSVID{
				IssuedAt:  mockClk.Now().Add(-1 * time.Hour),
				ExpiresAt: mockClk.Now().Add(-30 * time.Minute),
			},
			shouldRotate: true,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			rs := NewRotationStrategy(tc.availabilityTarget)
			actual := rs.JWTSVIDExpiresSoon(tc.token, mockClk.Now())
			assert.Equal(t, tc.shouldRotate, actual)
		})
	}
}
