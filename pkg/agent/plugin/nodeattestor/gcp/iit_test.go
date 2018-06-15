package gcp

import (
	"sync"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	cgcp "github.com/spiffe/spire/pkg/common/plugin/gcp"
	"github.com/stretchr/testify/require"
)

func TestErrorOnInvalidToken(t *testing.T) {
	p := &IITAttestorPlugin{
		mtx: &sync.RWMutex{},
	}

	_, err := p.BuildAttestationResponse([]byte("invalid"))
	require.Error(t, err)
}

func TestErrorOnMissingClaimsInIdentityToken(t *testing.T) {
	p := &IITAttestorPlugin{
		mtx: &sync.RWMutex{},
	}

	token := jwt.New(jwt.SigningMethodHS256)
	tokenString, _ := token.SignedString([]byte("secret"))
	_, err := p.BuildAttestationResponse([]byte(tokenString))
	require.Error(t, err)
}

func TestSuccessfulIdentityTokenProcessing(t *testing.T) {
	p := &IITAttestorPlugin{
		mtx: &sync.RWMutex{},
	}

	computEngine := &cgcp.ComputeEngine{
		ProjectID:  "project-123",
		InstanceID: "instance-123",
	}

	google := &cgcp.Google{
		ComputeEngine: *computEngine,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"google": google,
	})
	tokenString, _ := token.SignedString([]byte("secret"))
	res, err := p.BuildAttestationResponse([]byte(tokenString))
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotNil(t, res.GetSpiffeId)
}
