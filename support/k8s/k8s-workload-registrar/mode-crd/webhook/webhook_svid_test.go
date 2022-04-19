package webhook

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	spiretypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

const (
	Cluster            = "test-cluster"
	Namespace          = "test"
	WebhookServiceName = "k8s-workload-registrar"
	keyRSA             = "testdata/key-pkcs8-rsa.pem"
	certSingle         = "testdata/good-leaf-only.pem"
	keyECDSA           = "testdata/key-pkcs8-ecdsa.pem"
	certMultiple       = "testdata/good-leaf-and-intermediate.pem"
)

var (
	TrustDomain = spiffeid.RequireTrustDomainFromString("example.org")
)

func TestMintSVID(t *testing.T) {
	dir, err := os.MkdirTemp("", "svid-mint-test")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svidClient := &fakeSVIDClient{}
	webhookSVID, err := NewSVID(ctx, SVIDConfig{
		Cluster:            Cluster,
		Log:                plugin.NullLogger(),
		Namespace:          Namespace,
		S:                  svidClient,
		TrustDomain:        TrustDomain,
		WebhookCertDir:     dir,
		WebhookServiceName: WebhookServiceName,
	})
	require.NoError(t, err)

	tests := []struct {
		name       string
		keyPath    string
		certsPath  string
		errorCount int
	}{
		{
			name:       "Single certificate and key",
			keyPath:    keyRSA,
			certsPath:  certSingle,
			errorCount: 0,
		},
		{
			name:       "Single certificate and key with error retry",
			keyPath:    keyRSA,
			certsPath:  certSingle,
			errorCount: 2,
		},
		{
			name:       "Multiple certificates and key",
			keyPath:    keyECDSA,
			certsPath:  certMultiple,
			errorCount: 0,
		},
		{
			name:       "Multiple certificates and key with error retry",
			keyPath:    keyECDSA,
			certsPath:  certMultiple,
			errorCount: 3,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			svid, err := x509svid.Load(test.certsPath, test.keyPath)
			require.NoError(t, err)
			svidClient.setX509SVIDResponse(svid)
			svidClient.setErrorCount(test.errorCount)
			webhookSVID.certHalfLife = time.Time{}
			webhookSVID.notAfter = time.Time{}

			err = webhookSVID.MintSVID(ctx, svid.PrivateKey)
			require.NoError(t, err)

			actualSvid, err := x509svid.Load(filepath.Join(dir, certsFileName), filepath.Join(dir, keyFileName))
			require.NoError(t, err)
			require.Equal(t, svid, actualSvid)
		})
	}
}

func TestMintSVIDRetryLimit(t *testing.T) {
	dir, err := os.MkdirTemp("", "svid-retry-limit-test")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svidClient := &fakeSVIDClient{}
	webhookSVID, err := NewSVID(ctx, SVIDConfig{
		Cluster:            Cluster,
		Log:                plugin.NullLogger(),
		Namespace:          Namespace,
		S:                  svidClient,
		TrustDomain:        TrustDomain,
		WebhookCertDir:     dir,
		WebhookServiceName: WebhookServiceName,
	})
	require.NoError(t, err)

	svidClient.setErrorCount(11)
	err = webhookSVID.MintSVID(ctx, nil)
	require.Equal(t, err.Error(), "unable to make Mint SVID Request: test error")
}

func TestMintSVIDEmptyCertChain(t *testing.T) {
	dir, err := os.MkdirTemp("", "svid-empty-cert-chain-test")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svidClient := &fakeSVIDClient{}
	webhookSVID, err := NewSVID(ctx, SVIDConfig{
		Cluster:            Cluster,
		Log:                plugin.NullLogger(),
		Namespace:          Namespace,
		S:                  svidClient,
		TrustDomain:        TrustDomain,
		WebhookCertDir:     dir,
		WebhookServiceName: WebhookServiceName,
	})
	require.NoError(t, err)

	svidClient.setX509SVIDResponse(&x509svid.SVID{})
	err = webhookSVID.MintSVID(ctx, nil)
	require.Equal(t, err.Error(), "no certificates in Mint SVID Response")
}

type fakeSVIDClient struct {
	svid       *x509svid.SVID
	errorCount int
}

func (s *fakeSVIDClient) MintX509SVID(ctx context.Context, in *svidv1.MintX509SVIDRequest, opts ...grpc.CallOption) (*svidv1.MintX509SVIDResponse, error) {
	if s.errorCount > 0 {
		s.errorCount--

		return nil, errors.New("test error")
	}

	var svid spiretypes.X509SVID
	for _, cert := range s.svid.Certificates {
		svid.CertChain = append(svid.CertChain, cert.Raw)
	}

	return &svidv1.MintX509SVIDResponse{
		Svid: &svid,
	}, nil
}

func (s *fakeSVIDClient) MintJWTSVID(ctx context.Context, in *svidv1.MintJWTSVIDRequest, opts ...grpc.CallOption) (*svidv1.MintJWTSVIDResponse, error) {
	return nil, nil
}

func (s *fakeSVIDClient) BatchNewX509SVID(ctx context.Context, in *svidv1.BatchNewX509SVIDRequest, opts ...grpc.CallOption) (*svidv1.BatchNewX509SVIDResponse, error) {
	return nil, nil
}

func (s *fakeSVIDClient) NewJWTSVID(ctx context.Context, in *svidv1.NewJWTSVIDRequest, opts ...grpc.CallOption) (*svidv1.NewJWTSVIDResponse, error) {
	return nil, nil
}

func (s *fakeSVIDClient) NewDownstreamX509CA(ctx context.Context, in *svidv1.NewDownstreamX509CARequest, opts ...grpc.CallOption) (*svidv1.NewDownstreamX509CAResponse, error) {
	return nil, nil
}

func (s *fakeSVIDClient) setX509SVIDResponse(svid *x509svid.SVID) {
	s.svid = svid
}

func (s *fakeSVIDClient) setErrorCount(errorCount int) {
	s.errorCount = errorCount
}
