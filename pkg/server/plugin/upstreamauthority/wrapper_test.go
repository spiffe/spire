package upstreamauthority

import (
	"context"
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/spiffe/spire/.cache/cache/src/https-github.com-stretchr-testify/require"
	"github.com/spiffe/spire/test/fakes/fakeupstreamca"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
	"google.golang.org/grpc/codes"
)

var ctx = context.Background()

func TestMintX509CA(t *testing.T) {
	csr, pubKey, err := util.NewCSRTemplate("spiffe://domain.test")
	require.NoError(t, err)

	csrAnotherTD, _, err := util.NewCSRTemplate("spiffe://another-td")
	require.NoError(t, err)

	testCases := []struct {
		name   string
		req    *MintX509CARequest
		config fakeupstreamca.Config
		pubKey crypto.PublicKey
		err    string
	}{
		{
			name: "upstream without intermediate",
			req: &MintX509CARequest{
				Csr: csr,
			},
			pubKey: pubKey,
			config: fakeupstreamca.Config{
				TrustDomain: "domain.test",
			},
		},
		{
			name: "upstream with intermediate",
			req: &MintX509CARequest{
				Csr: csr,
			},
			pubKey: pubKey,
			config: fakeupstreamca.Config{
				TrustDomain:     "domain.test",
				UseIntermediate: true,
			},
		},
		{
			name: "another trust domain",
			req: &MintX509CARequest{
				Csr: csrAnotherTD,
			},
			err: "\"spiffe://another-td\" does not belong to trust domain \"domain.test\"",
			config: fakeupstreamca.Config{
				TrustDomain: "domain.test",
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			upstreamCA := fakeupstreamca.New(t, testCase.config)
			wrapper := Wrap(upstreamCA)

			resp, err := wrapper.MintX509CA(ctx, testCase.req)
			if testCase.err != "" {
				spiretest.AssertErrorContains(t, err, testCase.err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)

			validateX509CaChain(t, resp.X509CaChain, testCase.pubKey, testCase.config.UseIntermediate, upstreamCA)

			require.Len(t, resp.UpstreamX509Roots, 1)
			bundle, err := x509.ParseCertificate(resp.UpstreamX509Roots[0])
			require.NoError(t, err)
			require.Equal(t, upstreamCA.Root(), bundle)
		})
	}
}

func TestPublishX509CA(t *testing.T) {
	upstreamCA := fakeupstreamca.New(t, fakeupstreamca.Config{
		TrustDomain:     "domain.test",
		UseIntermediate: true,
	})
	wrapper := Wrap(upstreamCA)

	resp, err := wrapper.PublishX509CA(ctx, &PublishX509CARequest{})
	require.Nil(t, resp, "no response expected")

	spiretest.RequireGRPCStatus(t, err, codes.Unimplemented, "publishing upstream is unsupported")
}

func TestPublishJWTKey(t *testing.T) {
	upstreamCA := fakeupstreamca.New(t, fakeupstreamca.Config{
		TrustDomain:     "domain.test",
		UseIntermediate: true,
	})
	wrapper := Wrap(upstreamCA)

	resp, err := wrapper.PublishJWTKey(ctx, &PublishJWTKeyRequest{})
	require.Nil(t, resp, "no response expected")

	spiretest.RequireGRPCStatus(t, err, codes.Unimplemented, "publishing upstream is unsupported")
}

func validateX509CaChain(t *testing.T, caChain [][]byte, pubKey crypto.PublicKey, useIntermediate bool, upstreamCA *fakeupstreamca.UpstreamCA) {
	chain, err := x509.ParseCertificate(caChain[0])
	require.NoError(t, err)
	require.Equal(t, pubKey, chain.PublicKey)

	if useIntermediate {
		require.Len(t, caChain, 2)
		require.Equal(t, upstreamCA.Intermediate().Subject, chain.Issuer)

		intermediate, err := x509.ParseCertificate(caChain[1])
		require.NoError(t, err)
		require.Equal(t, upstreamCA.Intermediate(), intermediate)
		return
	}

	require.Len(t, caChain, 1)
	require.Equal(t, upstreamCA.Root().Subject, chain.Issuer)
}
