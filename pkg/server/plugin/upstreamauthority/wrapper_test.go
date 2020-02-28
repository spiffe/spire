package upstreamauthority

import (
	"context"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/spiffe/spire/pkg/server/plugin/upstreamca"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

var (
	ctx = context.Background()
	ca1 = pemBytes([]byte(`-----BEGIN CERTIFICATE-----
MIIBVzCB4gIJAJur7ujAmyDhMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNVBAMMCFRF
U1RST09UMB4XDTE4MTAxNTE4NDQxMVoXDTE5MTAxNTE4NDQxMVowEzERMA8GA1UE
AwwIVEVTVFJPT1QwfDANBgkqhkiG9w0BAQEFAANrADBoAmEAoYPq4DlrjDhanDM4
gDbEefDYi4IOmwUkQPAiJgQ2+CRm/pb/qc2zuj5FQZps1jxt3VtoDJnwfJuX6B4M
Zq0dHJF0ykfVonfxJbQsynge7yYA1avCLjlOv72Sk9/U8UQhAgMBAAEwDQYJKoZI
hvcNAQELBQADYQAXWlJO3EoYW3Uss0QjlqJJCC2M21HkF1AkWP6mUDgQ0PtbH2Vu
P58nzUo3Kzc3mfg3hocdt7vCDm75zdhjoDTLrT9IgU2XbDcbZF+yg51HZstonDiM
3JzUe9WQUljuQlM=
-----END CERTIFICATE-----
`))
	ca2 = pemBytes([]byte(`-----BEGIN CERTIFICATE-----
MIIBWTCB5AIJAOIaaEWcPCB2MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCVRF
U1RST09UMjAeFw0xODEwMTUxODQ0MjdaFw0xOTEwMTUxODQ0MjdaMBQxEjAQBgNV
BAMMCVRFU1RST09UMjB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQCmsAlaUc8YCFs5
hl44gZ3CJvpR0Yc4DAQkgSfed06iN0rmBuQzeCl3hiJ9ogqw4va2ciVQ8hTPeMw6
047YCMKOkmhDa4dFgGzk9GlvUQF5qft1MTWYlCI6/jEfx4Zsd4ECAwEAATANBgkq
hkiG9w0BAQsFAANhADQochC62F37uubcBDR70qhJlC7Bsz/KgxtduQR4pSOj4uZh
zFHHu+k8dS32+KooMqtUp71bhMgtlvYIRay4OMD6VurfP70caOHkCVFPxibAW9o9
NbyKVndd7aGvTed1PQ==
-----END CERTIFICATE-----
`))
)

func TestMintX509CA(t *testing.T) {
	testCases := []struct {
		// Test case name
		name string
		// Expected error
		err string
		// Certificate signing request presented to upstreamCA
		csr []byte
		// Preferred TTL  presented to upstreamCA
		preferredTTL int32
		// Error returned from upstreamCA
		upstreamErr error
		// Cert chain returned by upstreamCA
		certChain [][]byte
		// Bundle returned by upstreamCA
		bundle [][]byte
	}{
		{
			name:         "upstream success",
			csr:          []byte("some csr"),
			preferredTTL: 1,
			certChain:    [][]byte{ca1, ca2},
			bundle:       [][]byte{ca1, ca2},
		},
		{
			name: "upstreamca returns error",
			csr:  []byte("some csr"),
			err:  "upstreamauthority-wrapper: unable to submit csr: some error",

			upstreamErr: errors.New("some error"),
		},
		{
			name: "upstreamca invalid cert chain",
			csr:  []byte("some csr"),
			err:  "upstreamauthority-wrapper: unable to parse cert chain",

			certChain: [][]byte{[]byte("some invalid certchain")},
			bundle:    [][]byte{ca1},
		},
		{
			name: "upstreamca invalid bundle",
			csr:  []byte("some csr"),
			err:  "upstreamauthority-wrapper: unable to parse bundle",

			certChain: [][]byte{ca2},
			bundle:    [][]byte{[]byte("some invalid certchain")},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			// Create a fake upstream, it will return error or CAs depending expected result
			upstreamCA := &fakeUpstreamCA{
				t:            t,
				csr:          testCase.csr,
				preferredTTL: testCase.preferredTTL,
				err:          testCase.upstreamErr,
				certChain:    testCase.certChain,
				bundle:       testCase.bundle,
			}
			// Create wrapper using fake UpstreamCA
			wrapper := Wrap(upstreamCA)

			// Request Mint to wrapper
			resp, err := wrapper.MintX509CA(ctx, &MintX509CARequest{
				Csr:          testCase.csr,
				PreferredTtl: testCase.preferredTTL,
			})

			// if test case expect an error validates it has expected code and message
			if testCase.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, codes.Internal, testCase.err)
				return
			}

			// No error expected and response must not be nil
			require.NoError(t, err)
			require.NotNil(t, resp)

			// Mint must return an array of []byte, instead of a single []byte
			require.Equal(t, testCase.certChain, resp.X509CaChain)
			require.Equal(t, testCase.bundle, resp.UpstreamX509Roots)
		})
	}
}

func TestPublishJWTKey(t *testing.T) {
	wrapper := Wrap(&fakeUpstreamCA{})

	resp, err := wrapper.PublishJWTKey(ctx, &PublishJWTKeyRequest{})
	require.Nil(t, resp, "no response expected")

	spiretest.RequireGRPCStatus(t, err, codes.Unimplemented, "upstreamauthority-wrapper: publishing upstream is unsupported")
}

// fakeUpstreamCA is a custom UpstreamCA that returns error or response depending on its configurations
type fakeUpstreamCA struct {
	t *testing.T

	// request parameters
	csr          []byte
	preferredTTL int32

	// fake will return error as response of SubmitCSR in case it is defined
	err       error
	certChain [][]byte
	bundle    [][]byte
}

// SubmitCSR process fake configurations in order to return an error or certChain and bundle in a single []byte
// it validates if request provided expected values
func (f *fakeUpstreamCA) SubmitCSR(ctx context.Context, req *upstreamca.SubmitCSRRequest) (*upstreamca.SubmitCSRResponse, error) {
	// Returns error if it is expected
	if f.err != nil {
		return nil, f.err
	}

	// Validates request
	require.Equal(f.t, f.csr, req.Csr)
	require.Equal(f.t, f.preferredTTL, req.PreferredTtl)

	// Concatenate certChain into a single []byte
	var certChain []byte
	for _, b := range f.certChain {
		certChain = append(certChain, b...)
	}

	// Concatenate certChain into a single []byte
	var bundle []byte
	for _, b := range f.bundle {
		bundle = append(bundle, b...)
	}

	return &upstreamca.SubmitCSRResponse{
		SignedCertificate: &upstreamca.SignedCertificate{
			CertChain: certChain,
			Bundle:    bundle,
		},
	}, nil
}

func pemBytes(p []byte) []byte {
	b, _ := pem.Decode(p)
	if b != nil {
		return b.Bytes
	}
	return nil
}
