package credentialcomposer_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	credentialcomposerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/credentialcomposer/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/credentialcomposer"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	publicKey         = testkey.MustEC256().Public()
	publicKeyBytes, _ = x509.MarshalPKIXPublicKey(publicKey)

	subject1 = pkix.Name{
		Country:            []string{"C1"},
		Organization:       []string{"O1"},
		OrganizationalUnit: []string{"OU1"},
		Locality:           []string{"L1"},
		Province:           []string{"P1"},
		StreetAddress:      []string{"SA1"},
		PostalCode:         []string{"PC1"},
		SerialNumber:       "SN1",
		CommonName:         "CN1",
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: "EXTRA1"},
		},
	}

	subject1v1 = &credentialcomposerv1.DistinguishedName{
		Country:            []string{"C1"},
		Organization:       []string{"O1"},
		OrganizationalUnit: []string{"OU1"},
		Locality:           []string{"L1"},
		Province:           []string{"P1"},
		StreetAddress:      []string{"SA1"},
		PostalCode:         []string{"PC1"},
		SerialNumber:       "SN1",
		CommonName:         "CN1",
		ExtraNames: []*credentialcomposerv1.AttributeTypeAndValue{
			{Oid: "1.2.3.4", StringValue: "EXTRA1"},
		},
	}

	subject2 = pkix.Name{
		Country:            []string{"C2"},
		Organization:       []string{"O2"},
		OrganizationalUnit: []string{"OU2"},
		Locality:           []string{"L2"},
		Province:           []string{"P2"},
		StreetAddress:      []string{"SA2"},
		PostalCode:         []string{"PC2"},
		SerialNumber:       "SN2",
		CommonName:         "CN2",
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{4, 3, 2, 1}, Value: "EXTRA2"},
		},
	}

	subject2v1 = &credentialcomposerv1.DistinguishedName{
		Country:            []string{"C2"},
		Organization:       []string{"O2"},
		OrganizationalUnit: []string{"OU2"},
		Locality:           []string{"L2"},
		Province:           []string{"P2"},
		StreetAddress:      []string{"SA2"},
		PostalCode:         []string{"PC2"},
		SerialNumber:       "SN2",
		CommonName:         "CN2",
		ExtraNames: []*credentialcomposerv1.AttributeTypeAndValue{
			{Oid: "4.3.2.1", StringValue: "EXTRA2"},
		},
	}
)

func TestV1ComposeServerX509CA(t *testing.T) {
	for _, tt := range []struct {
		test      string
		pluginErr error

		attributesIn    credentialcomposer.X509CAAttributes
		expectRequestIn *credentialcomposerv1.ComposeServerX509CARequest

		responseOut         *credentialcomposerv1.ComposeServerX509CAResponse
		expectAttributesOut credentialcomposer.X509CAAttributes

		expectCode    codes.Code
		expectMessage string
	}{
		{
			test:          "plugin fails",
			pluginErr:     status.Error(codes.Internal, "oh no"),
			expectCode:    codes.Internal,
			expectMessage: "credentialcomposer(test): oh no",
		},
		{
			test: "invalid subject extra names input",
			attributesIn: credentialcomposer.X509CAAttributes{
				Subject: pkix.Name{
					ExtraNames: []pkix.AttributeTypeAndValue{
						{Value: 3}, // only string values are allowed
					},
				},
			},
			expectCode:    codes.Internal,
			expectMessage: "credentialcomposer(test): invalid X509CA attributes: only string values are allowed in extra name attributes",
		},
		{
			test:      "attributes unchanged if unimplemented",
			pluginErr: status.Error(codes.Unimplemented, "not implemented"),
			attributesIn: credentialcomposer.X509CAAttributes{
				Subject: subject1,
			},
			expectRequestIn: &credentialcomposerv1.ComposeServerX509CARequest{
				Attributes: &credentialcomposerv1.X509CAAttributes{
					Subject: subject1v1,
				},
			},
			expectAttributesOut: credentialcomposer.X509CAAttributes{
				Subject: subject1,
			},
		},
		{
			test: "attributes unchanged if plugin does not respond with attributes",
			attributesIn: credentialcomposer.X509CAAttributes{
				Subject: subject1,
			},
			expectRequestIn: &credentialcomposerv1.ComposeServerX509CARequest{
				Attributes: &credentialcomposerv1.X509CAAttributes{
					Subject: subject1v1,
				},
			},
			responseOut: &credentialcomposerv1.ComposeServerX509CAResponse{},
			expectAttributesOut: credentialcomposer.X509CAAttributes{
				Subject: subject1,
			},
		},
		{
			test: "attributes overridden by plugin",
			attributesIn: credentialcomposer.X509CAAttributes{
				Subject:         subject1,
				Policies:        []x509.OID{makeOID(t, 1, 2, 3, 4)},
				ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte("ORIGINAL")}},
			},
			expectRequestIn: &credentialcomposerv1.ComposeServerX509CARequest{
				Attributes: &credentialcomposerv1.X509CAAttributes{
					Subject:           subject1v1,
					PolicyIdentifiers: []string{"1.2.3.4"},
					ExtraExtensions: []*credentialcomposerv1.X509Extension{
						{
							Critical: false,
							Oid:      "1.2.3.4",
							Value:    []byte("ORIGINAL"),
						},
					},
				},
			},
			responseOut: &credentialcomposerv1.ComposeServerX509CAResponse{
				Attributes: &credentialcomposerv1.X509CAAttributes{
					Subject:           subject2v1,
					PolicyIdentifiers: []string{"2.3.4.5"},
					ExtraExtensions: []*credentialcomposerv1.X509Extension{
						{
							Critical: true,
							Oid:      "2.3.4.5",
							Value:    []byte("NEW"),
						},
					},
				},
			},
			expectAttributesOut: credentialcomposer.X509CAAttributes{
				Subject:         subject2,
				Policies:        []x509.OID{makeOID(t, 2, 3, 4, 5)},
				ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 3, 4, 5}, Value: []byte("NEW"), Critical: true}},
			},
		},
		{
			test: "plugin returns invalid attributes subject extra name",
			attributesIn: credentialcomposer.X509CAAttributes{
				Subject: subject1,
			},
			responseOut: &credentialcomposerv1.ComposeServerX509CAResponse{
				Attributes: &credentialcomposerv1.X509CAAttributes{
					Subject: &credentialcomposerv1.DistinguishedName{
						ExtraNames: []*credentialcomposerv1.AttributeTypeAndValue{
							{Oid: "NOT AN OID"},
						},
					},
				},
			},
			expectCode:    codes.Internal,
			expectMessage: `credentialcomposer(test): plugin returned invalid X509CA attributes: subject: extra names: invalid OID: non-integer part "NOT AN OID"`,
		},
		{
			test: "plugin returns invalid attributes policy identifiers",
			attributesIn: credentialcomposer.X509CAAttributes{
				Subject: subject1,
			},
			responseOut: &credentialcomposerv1.ComposeServerX509CAResponse{
				Attributes: &credentialcomposerv1.X509CAAttributes{
					Subject:           subject1v1,
					PolicyIdentifiers: []string{"NOT AN OID"},
				},
			},
			expectCode:    codes.Internal,
			expectMessage: `credentialcomposer(test): plugin returned invalid X509CA attributes: policy identifiers: invalid oid`,
		},
		{
			test: "plugin returns invalid attributes extra extensions",
			attributesIn: credentialcomposer.X509CAAttributes{
				Subject: subject1,
			},
			responseOut: &credentialcomposerv1.ComposeServerX509CAResponse{
				Attributes: &credentialcomposerv1.X509CAAttributes{
					Subject: subject1v1,
					ExtraExtensions: []*credentialcomposerv1.X509Extension{
						{Oid: "NOT AN OID"},
					},
				},
			},
			expectCode:    codes.Internal,
			expectMessage: `credentialcomposer(test): plugin returned invalid X509CA attributes: extra extensions: invalid OID: non-integer part "NOT AN OID"`,
		},
	} {
		t.Run(tt.test, func(t *testing.T) {
			plugin := &fakeV1Plugin{err: tt.pluginErr, composeServerX509CAResponseOut: tt.responseOut}
			cc := loadV1Plugin(t, plugin)
			attributesOut, err := cc.ComposeServerX509CA(context.Background(), tt.attributesIn)
			if tt.expectCode != codes.OK {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMessage)
				return
			}
			require.NoError(t, err)
			spiretest.AssertProtoEqual(t, plugin.composeServerX509CARequestIn, tt.expectRequestIn)
			assert.Equal(t, attributesOut, tt.expectAttributesOut)
		})
	}
}

func TestV1ComposeServerX509SVID(t *testing.T) {
	for _, tt := range []struct {
		test      string
		pluginErr error

		attributesIn    credentialcomposer.X509SVIDAttributes
		expectRequestIn *credentialcomposerv1.ComposeServerX509SVIDRequest

		responseOut         *credentialcomposerv1.ComposeServerX509SVIDResponse
		expectAttributesOut credentialcomposer.X509SVIDAttributes

		expectCode    codes.Code
		expectMessage string
	}{
		{
			test:          "plugin fails",
			pluginErr:     status.Error(codes.Internal, "oh no"),
			expectCode:    codes.Internal,
			expectMessage: "credentialcomposer(test): oh no",
		},
		{
			test: "invalid subject extra names input",
			attributesIn: credentialcomposer.X509SVIDAttributes{
				Subject: pkix.Name{
					ExtraNames: []pkix.AttributeTypeAndValue{
						{Value: 3}, // only string values are allowed
					},
				},
			},
			expectCode:    codes.Internal,
			expectMessage: "credentialcomposer(test): invalid server X509SVID attributes: only string values are allowed in extra name attributes",
		},
		{
			test:      "attributes unchanged if unimplemented",
			pluginErr: status.Error(codes.Unimplemented, "not implemented"),
			attributesIn: credentialcomposer.X509SVIDAttributes{
				Subject: subject1,
			},
			expectRequestIn: &credentialcomposerv1.ComposeServerX509SVIDRequest{
				Attributes: &credentialcomposerv1.X509SVIDAttributes{
					Subject: subject1v1,
				},
			},
			responseOut: &credentialcomposerv1.ComposeServerX509SVIDResponse{},
			expectAttributesOut: credentialcomposer.X509SVIDAttributes{
				Subject: subject1,
			},
		},
		{
			test: "attributes unchanged if plugin does not respond with attributes",
			attributesIn: credentialcomposer.X509SVIDAttributes{
				Subject: subject1,
			},
			expectRequestIn: &credentialcomposerv1.ComposeServerX509SVIDRequest{
				Attributes: &credentialcomposerv1.X509SVIDAttributes{
					Subject: subject1v1,
				},
			},
			responseOut: &credentialcomposerv1.ComposeServerX509SVIDResponse{},
			expectAttributesOut: credentialcomposer.X509SVIDAttributes{
				Subject: subject1,
			},
		},
		{
			test: "attributes overridden by plugin",
			attributesIn: credentialcomposer.X509SVIDAttributes{
				Subject:         subject1,
				ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte("ORIGINAL")}},
			},
			expectRequestIn: &credentialcomposerv1.ComposeServerX509SVIDRequest{
				Attributes: &credentialcomposerv1.X509SVIDAttributes{
					Subject: subject1v1,
					ExtraExtensions: []*credentialcomposerv1.X509Extension{
						{
							Critical: false,
							Oid:      "1.2.3.4",
							Value:    []byte("ORIGINAL"),
						},
					},
				},
			},
			responseOut: &credentialcomposerv1.ComposeServerX509SVIDResponse{
				Attributes: &credentialcomposerv1.X509SVIDAttributes{
					Subject: subject2v1,
					ExtraExtensions: []*credentialcomposerv1.X509Extension{
						{
							Critical: true,
							Oid:      "4.3.2.1",
							Value:    []byte("NEW"),
						},
					},
				},
			},
			expectAttributesOut: credentialcomposer.X509SVIDAttributes{
				Subject:         subject2,
				ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{4, 3, 2, 1}, Value: []byte("NEW"), Critical: true}},
			},
		},
		{
			test: "plugin returns invalid attributes subject",
			attributesIn: credentialcomposer.X509SVIDAttributes{
				Subject: subject1,
			},
			responseOut: &credentialcomposerv1.ComposeServerX509SVIDResponse{
				Attributes: &credentialcomposerv1.X509SVIDAttributes{
					Subject: &credentialcomposerv1.DistinguishedName{
						ExtraNames: []*credentialcomposerv1.AttributeTypeAndValue{
							{Oid: "NOT AN OID"},
						},
					},
				},
			},
			expectCode:    codes.Internal,
			expectMessage: `credentialcomposer(test): plugin returned invalid X509SVID attributes: subject: extra names: invalid OID: non-integer part "NOT AN OID"`,
		},
		{
			test: "plugin returns invalid attributes extra extensions",
			attributesIn: credentialcomposer.X509SVIDAttributes{
				Subject: subject1,
			},
			responseOut: &credentialcomposerv1.ComposeServerX509SVIDResponse{
				Attributes: &credentialcomposerv1.X509SVIDAttributes{
					Subject: &credentialcomposerv1.DistinguishedName{CommonName: "ORIGINAL"},
					ExtraExtensions: []*credentialcomposerv1.X509Extension{
						{Oid: "NOT AN OID"},
					},
				},
			},
			expectCode:    codes.Internal,
			expectMessage: `credentialcomposer(test): plugin returned invalid X509SVID attributes: extra extensions: invalid OID: non-integer part "NOT AN OID"`,
		},
	} {
		t.Run(tt.test, func(t *testing.T) {
			plugin := &fakeV1Plugin{err: tt.pluginErr, composeServerX509SVIDResponseOut: tt.responseOut}
			cc := loadV1Plugin(t, plugin)
			attributesOut, err := cc.ComposeServerX509SVID(context.Background(), tt.attributesIn)
			if tt.expectCode != codes.OK {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMessage)
				return
			}
			require.NoError(t, err)
			spiretest.AssertProtoEqual(t, plugin.composeServerX509SVIDRequestIn, tt.expectRequestIn)
			assert.Equal(t, attributesOut, tt.expectAttributesOut)
		})
	}
}

func TestV1ComposeAgentX509SVID(t *testing.T) {
	id := spiffeid.RequireFromString("spiffe://domain.test/spire/agent/foo")
	for _, tt := range []struct {
		test      string
		pluginErr error

		idIn            spiffeid.ID
		publicKeyIn     crypto.PublicKey
		attributesIn    credentialcomposer.X509SVIDAttributes
		expectRequestIn *credentialcomposerv1.ComposeAgentX509SVIDRequest

		responseOut         *credentialcomposerv1.ComposeAgentX509SVIDResponse
		expectAttributesOut credentialcomposer.X509SVIDAttributes

		expectCode    codes.Code
		expectMessage string
	}{
		{
			test:          "invalid ID",
			publicKeyIn:   publicKey,
			expectCode:    codes.Internal,
			expectMessage: "credentialcomposer(test): invalid agent ID: empty",
		},
		{
			test:          "invalid public key",
			idIn:          id,
			expectCode:    codes.Internal,
			expectMessage: "credentialcomposer(test): invalid agent X509SVID public key: x509: unsupported public key type: <nil>",
		},
		{
			test:          "plugin fails",
			idIn:          id,
			publicKeyIn:   publicKey,
			pluginErr:     status.Error(codes.Internal, "oh no"),
			expectCode:    codes.Internal,
			expectMessage: "credentialcomposer(test): oh no",
		},
		{
			test:        "invalid subject extra names input",
			idIn:        id,
			publicKeyIn: publicKey,
			attributesIn: credentialcomposer.X509SVIDAttributes{
				Subject: pkix.Name{
					ExtraNames: []pkix.AttributeTypeAndValue{
						{Value: 3}, // only string values are allowed
					},
				},
			},
			expectCode:    codes.Internal,
			expectMessage: "credentialcomposer(test): invalid agent X509SVID attributes: only string values are allowed in extra name attributes",
		},
		{
			test:        "attributes unchanged if unimplemented",
			pluginErr:   status.Error(codes.Unimplemented, "not implemented"),
			idIn:        id,
			publicKeyIn: publicKey,
			attributesIn: credentialcomposer.X509SVIDAttributes{
				Subject: subject1,
			},
			expectRequestIn: &credentialcomposerv1.ComposeAgentX509SVIDRequest{
				SpiffeId:  id.String(),
				PublicKey: publicKeyBytes,
				Attributes: &credentialcomposerv1.X509SVIDAttributes{
					Subject: subject1v1,
				},
			},
			responseOut: &credentialcomposerv1.ComposeAgentX509SVIDResponse{},
			expectAttributesOut: credentialcomposer.X509SVIDAttributes{
				Subject: subject1,
			},
		},
		{
			test:        "attributes unchanged if plugin does not respond with attributes",
			idIn:        id,
			publicKeyIn: publicKey,
			attributesIn: credentialcomposer.X509SVIDAttributes{
				Subject: subject1,
			},
			expectRequestIn: &credentialcomposerv1.ComposeAgentX509SVIDRequest{
				SpiffeId:  id.String(),
				PublicKey: publicKeyBytes,
				Attributes: &credentialcomposerv1.X509SVIDAttributes{
					Subject: subject1v1,
				},
			},
			responseOut: &credentialcomposerv1.ComposeAgentX509SVIDResponse{},
			expectAttributesOut: credentialcomposer.X509SVIDAttributes{
				Subject: subject1,
			},
		},
		{
			test:        "attributes overridden by plugin",
			idIn:        id,
			publicKeyIn: publicKey,
			attributesIn: credentialcomposer.X509SVIDAttributes{
				Subject:         subject1,
				ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte("ORIGINAL")}},
			},
			expectRequestIn: &credentialcomposerv1.ComposeAgentX509SVIDRequest{
				SpiffeId:  id.String(),
				PublicKey: publicKeyBytes,
				Attributes: &credentialcomposerv1.X509SVIDAttributes{
					Subject: subject1v1,
					ExtraExtensions: []*credentialcomposerv1.X509Extension{
						{
							Critical: false,
							Oid:      "1.2.3.4",
							Value:    []byte("ORIGINAL"),
						},
					},
				},
			},
			responseOut: &credentialcomposerv1.ComposeAgentX509SVIDResponse{
				Attributes: &credentialcomposerv1.X509SVIDAttributes{
					Subject: subject2v1,
					ExtraExtensions: []*credentialcomposerv1.X509Extension{
						{
							Critical: true,
							Oid:      "4.3.2.1",
							Value:    []byte("NEW"),
						},
					},
				},
			},
			expectAttributesOut: credentialcomposer.X509SVIDAttributes{
				Subject:         subject2,
				ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{4, 3, 2, 1}, Value: []byte("NEW"), Critical: true}},
			},
		},
		{
			test:        "plugin returns invalid attributes subject",
			idIn:        id,
			publicKeyIn: publicKey,
			attributesIn: credentialcomposer.X509SVIDAttributes{
				Subject: subject1,
			},
			responseOut: &credentialcomposerv1.ComposeAgentX509SVIDResponse{
				Attributes: &credentialcomposerv1.X509SVIDAttributes{
					Subject: &credentialcomposerv1.DistinguishedName{
						ExtraNames: []*credentialcomposerv1.AttributeTypeAndValue{
							{Oid: "NOT AN OID"},
						},
					},
				},
			},
			expectCode:    codes.Internal,
			expectMessage: `credentialcomposer(test): plugin returned invalid X509SVID attributes: subject: extra names: invalid OID: non-integer part "NOT AN OID"`,
		},
		{
			test:        "plugin returns invalid attributes extra extensions",
			idIn:        id,
			publicKeyIn: publicKey,
			attributesIn: credentialcomposer.X509SVIDAttributes{
				Subject: subject1,
			},
			responseOut: &credentialcomposerv1.ComposeAgentX509SVIDResponse{
				Attributes: &credentialcomposerv1.X509SVIDAttributes{
					Subject: &credentialcomposerv1.DistinguishedName{CommonName: "ORIGINAL"},
					ExtraExtensions: []*credentialcomposerv1.X509Extension{
						{Oid: "NOT AN OID"},
					},
				},
			},
			expectCode:    codes.Internal,
			expectMessage: `credentialcomposer(test): plugin returned invalid X509SVID attributes: extra extensions: invalid OID: non-integer part "NOT AN OID"`,
		},
	} {
		t.Run(tt.test, func(t *testing.T) {
			plugin := &fakeV1Plugin{err: tt.pluginErr, composeAgentX509SVIDResponseOut: tt.responseOut}
			cc := loadV1Plugin(t, plugin)
			attributesOut, err := cc.ComposeAgentX509SVID(context.Background(), tt.idIn, tt.publicKeyIn, tt.attributesIn)
			if tt.expectCode != codes.OK {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMessage)
				return
			}
			require.NoError(t, err)
			spiretest.AssertProtoEqual(t, plugin.composeAgentX509SVIDRequestIn, tt.expectRequestIn)
			assert.Equal(t, attributesOut, tt.expectAttributesOut)
		})
	}
}

func TestV1ComposeWorkloadX509SVID(t *testing.T) {
	id := spiffeid.RequireFromString("spiffe://domain.test/workload")
	for _, tt := range []struct {
		test      string
		pluginErr error

		idIn            spiffeid.ID
		publicKeyIn     crypto.PublicKey
		attributesIn    credentialcomposer.X509SVIDAttributes
		expectRequestIn *credentialcomposerv1.ComposeWorkloadX509SVIDRequest

		responseOut         *credentialcomposerv1.ComposeWorkloadX509SVIDResponse
		expectAttributesOut credentialcomposer.X509SVIDAttributes

		expectCode    codes.Code
		expectMessage string
	}{
		{
			test:          "invalid ID",
			publicKeyIn:   publicKey,
			expectCode:    codes.Internal,
			expectMessage: "credentialcomposer(test): invalid workload ID: empty",
		},
		{
			test:          "invalid public key",
			idIn:          id,
			expectCode:    codes.Internal,
			expectMessage: "credentialcomposer(test): invalid workload X509SVID public key: x509: unsupported public key type: <nil>",
		},
		{
			test:          "plugin fails",
			idIn:          id,
			publicKeyIn:   publicKey,
			pluginErr:     status.Error(codes.Internal, "oh no"),
			expectCode:    codes.Internal,
			expectMessage: "credentialcomposer(test): oh no",
		},
		{
			test:        "invalid subject extra names input",
			idIn:        id,
			publicKeyIn: publicKey,
			attributesIn: credentialcomposer.X509SVIDAttributes{
				Subject: pkix.Name{
					ExtraNames: []pkix.AttributeTypeAndValue{
						{Value: 3}, // only string values are allowed
					},
				},
			},
			expectCode:    codes.Internal,
			expectMessage: "credentialcomposer(test): invalid workload X509SVID attributes: only string values are allowed in extra name attributes",
		},
		{
			test:        "attributes unchanged if unimplemented",
			pluginErr:   status.Error(codes.Unimplemented, "not implemented"),
			idIn:        id,
			publicKeyIn: publicKey,
			attributesIn: credentialcomposer.X509SVIDAttributes{
				Subject: subject1,
			},
			expectRequestIn: &credentialcomposerv1.ComposeWorkloadX509SVIDRequest{
				SpiffeId:  id.String(),
				PublicKey: publicKeyBytes,
				Attributes: &credentialcomposerv1.X509SVIDAttributes{
					Subject: subject1v1,
				},
			},
			responseOut: &credentialcomposerv1.ComposeWorkloadX509SVIDResponse{},
			expectAttributesOut: credentialcomposer.X509SVIDAttributes{
				Subject: subject1,
			},
		},
		{
			test:        "attributes unchanged if plugin does not respond with attributes",
			idIn:        id,
			publicKeyIn: publicKey,
			attributesIn: credentialcomposer.X509SVIDAttributes{
				Subject: subject1,
			},
			expectRequestIn: &credentialcomposerv1.ComposeWorkloadX509SVIDRequest{
				SpiffeId:  id.String(),
				PublicKey: publicKeyBytes,
				Attributes: &credentialcomposerv1.X509SVIDAttributes{
					Subject: subject1v1,
				},
			},
			responseOut: &credentialcomposerv1.ComposeWorkloadX509SVIDResponse{},
			expectAttributesOut: credentialcomposer.X509SVIDAttributes{
				Subject: subject1,
			},
		},
		{
			test:        "attributes overridden by plugin",
			idIn:        id,
			publicKeyIn: publicKey,
			attributesIn: credentialcomposer.X509SVIDAttributes{
				Subject:         subject1,
				ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte("ORIGINAL")}},
			},
			expectRequestIn: &credentialcomposerv1.ComposeWorkloadX509SVIDRequest{
				SpiffeId:  id.String(),
				PublicKey: publicKeyBytes,
				Attributes: &credentialcomposerv1.X509SVIDAttributes{
					Subject: subject1v1,
					ExtraExtensions: []*credentialcomposerv1.X509Extension{
						{
							Critical: false,
							Oid:      "1.2.3.4",
							Value:    []byte("ORIGINAL"),
						},
					},
				},
			},
			responseOut: &credentialcomposerv1.ComposeWorkloadX509SVIDResponse{
				Attributes: &credentialcomposerv1.X509SVIDAttributes{
					Subject: subject2v1,
					ExtraExtensions: []*credentialcomposerv1.X509Extension{
						{
							Critical: true,
							Oid:      "4.3.2.1",
							Value:    []byte("NEW"),
						},
					},
				},
			},
			expectAttributesOut: credentialcomposer.X509SVIDAttributes{
				Subject:         subject2,
				ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{4, 3, 2, 1}, Value: []byte("NEW"), Critical: true}},
			},
		},
		{
			test:        "plugin returns invalid attributes subject",
			idIn:        id,
			publicKeyIn: publicKey,
			attributesIn: credentialcomposer.X509SVIDAttributes{
				Subject: subject1,
			},
			responseOut: &credentialcomposerv1.ComposeWorkloadX509SVIDResponse{
				Attributes: &credentialcomposerv1.X509SVIDAttributes{
					Subject: &credentialcomposerv1.DistinguishedName{
						ExtraNames: []*credentialcomposerv1.AttributeTypeAndValue{
							{Oid: "NOT AN OID"},
						},
					},
				},
			},
			expectCode:    codes.Internal,
			expectMessage: `credentialcomposer(test): plugin returned invalid X509SVID attributes: subject: extra names: invalid OID: non-integer part "NOT AN OID"`,
		},
		{
			test:        "plugin returns invalid attributes extra extensions",
			idIn:        id,
			publicKeyIn: publicKey,
			attributesIn: credentialcomposer.X509SVIDAttributes{
				Subject: subject1,
			},
			responseOut: &credentialcomposerv1.ComposeWorkloadX509SVIDResponse{
				Attributes: &credentialcomposerv1.X509SVIDAttributes{
					Subject: &credentialcomposerv1.DistinguishedName{CommonName: "ORIGINAL"},
					ExtraExtensions: []*credentialcomposerv1.X509Extension{
						{Oid: "NOT AN OID"},
					},
				},
			},
			expectCode:    codes.Internal,
			expectMessage: `credentialcomposer(test): plugin returned invalid X509SVID attributes: extra extensions: invalid OID: non-integer part "NOT AN OID"`,
		},
	} {
		t.Run(tt.test, func(t *testing.T) {
			plugin := &fakeV1Plugin{err: tt.pluginErr, composeWorkloadX509SVIDResponseOut: tt.responseOut}
			cc := loadV1Plugin(t, plugin)
			attributesOut, err := cc.ComposeWorkloadX509SVID(context.Background(), tt.idIn, tt.publicKeyIn, tt.attributesIn)
			if tt.expectCode != codes.OK {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMessage)
				return
			}
			require.NoError(t, err)
			spiretest.AssertProtoEqual(t, plugin.composeWorkloadX509SVIDRequestIn, tt.expectRequestIn)
			assert.Equal(t, attributesOut, tt.expectAttributesOut)
		})
	}
}

func TestV1ComposeWorkloadJWTSVID(t *testing.T) {
	id := spiffeid.RequireFromString("spiffe://domain.test/workload")
	for _, tt := range []struct {
		test      string
		pluginErr error

		idIn            spiffeid.ID
		attributesIn    credentialcomposer.JWTSVIDAttributes
		expectRequestIn *credentialcomposerv1.ComposeWorkloadJWTSVIDRequest

		responseOut         *credentialcomposerv1.ComposeWorkloadJWTSVIDResponse
		expectAttributesOut credentialcomposer.JWTSVIDAttributes

		expectCode    codes.Code
		expectMessage string
	}{
		{
			test:          "invalid ID",
			expectCode:    codes.Internal,
			expectMessage: "credentialcomposer(test): invalid workload ID: empty",
		},
		{
			test:          "plugin fails",
			idIn:          id,
			attributesIn:  credentialcomposer.JWTSVIDAttributes{Claims: map[string]any{"ORIGINAL_KEY": "ORIGINAL_VALUE"}},
			pluginErr:     status.Error(codes.Internal, "oh no"),
			expectCode:    codes.Internal,
			expectMessage: "credentialcomposer(test): oh no",
		},
		{
			test:          "invalid claims input",
			idIn:          id,
			attributesIn:  credentialcomposer.JWTSVIDAttributes{},
			expectCode:    codes.Internal,
			expectMessage: "credentialcomposer(test): invalid workload JWTSVID attributes: invalid claims: cannot be empty",
		},
		{
			test:         "attributes unchanged if unimplemented",
			pluginErr:    status.Error(codes.Unimplemented, "not implemented"),
			idIn:         id,
			attributesIn: credentialcomposer.JWTSVIDAttributes{Claims: map[string]any{"ORIGINAL_KEY": "ORIGINAL_VALUE"}},
			expectRequestIn: &credentialcomposerv1.ComposeWorkloadJWTSVIDRequest{
				SpiffeId: id.String(),
				Attributes: &credentialcomposerv1.JWTSVIDAttributes{
					Claims: &structpb.Struct{Fields: map[string]*structpb.Value{"ORIGINAL_KEY": structpb.NewStringValue("ORIGINAL_VALUE")}},
				},
			},
			responseOut:         &credentialcomposerv1.ComposeWorkloadJWTSVIDResponse{},
			expectAttributesOut: credentialcomposer.JWTSVIDAttributes{Claims: map[string]any{"ORIGINAL_KEY": "ORIGINAL_VALUE"}},
		},
		{
			test:         "attributes unchanged if plugin does not respond with attributes",
			idIn:         id,
			attributesIn: credentialcomposer.JWTSVIDAttributes{Claims: map[string]any{"ORIGINAL_KEY": "ORIGINAL_VALUE"}},
			expectRequestIn: &credentialcomposerv1.ComposeWorkloadJWTSVIDRequest{
				SpiffeId: id.String(),
				Attributes: &credentialcomposerv1.JWTSVIDAttributes{
					Claims: &structpb.Struct{Fields: map[string]*structpb.Value{"ORIGINAL_KEY": structpb.NewStringValue("ORIGINAL_VALUE")}},
				},
			},
			responseOut:         &credentialcomposerv1.ComposeWorkloadJWTSVIDResponse{},
			expectAttributesOut: credentialcomposer.JWTSVIDAttributes{Claims: map[string]any{"ORIGINAL_KEY": "ORIGINAL_VALUE"}},
		},
		{
			test:         "attributes overridden by plugin",
			idIn:         id,
			attributesIn: credentialcomposer.JWTSVIDAttributes{Claims: map[string]any{"ORIGINAL_KEY": "ORIGINAL_VALUE"}},
			expectRequestIn: &credentialcomposerv1.ComposeWorkloadJWTSVIDRequest{
				SpiffeId: id.String(),
				Attributes: &credentialcomposerv1.JWTSVIDAttributes{
					Claims: &structpb.Struct{Fields: map[string]*structpb.Value{"ORIGINAL_KEY": structpb.NewStringValue("ORIGINAL_VALUE")}},
				},
			},
			responseOut: &credentialcomposerv1.ComposeWorkloadJWTSVIDResponse{
				Attributes: &credentialcomposerv1.JWTSVIDAttributes{
					Claims: &structpb.Struct{Fields: map[string]*structpb.Value{"NEW_KEY": structpb.NewStringValue("NEW_VALUE")}},
				},
			},
			expectAttributesOut: credentialcomposer.JWTSVIDAttributes{Claims: map[string]any{"NEW_KEY": "NEW_VALUE"}},
		},
	} {
		t.Run(tt.test, func(t *testing.T) {
			plugin := &fakeV1Plugin{err: tt.pluginErr, composeWorkloadJWTSVIDResponseOut: tt.responseOut}
			cc := loadV1Plugin(t, plugin)
			attributesOut, err := cc.ComposeWorkloadJWTSVID(context.Background(), tt.idIn, tt.attributesIn)
			if tt.expectCode != codes.OK {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMessage)
				return
			}
			require.NoError(t, err)
			spiretest.AssertProtoEqual(t, plugin.composeWorkloadJWTSVIDRequestIn, tt.expectRequestIn)
			assert.Equal(t, attributesOut, tt.expectAttributesOut)
		})
	}
}

func loadV1Plugin(t *testing.T, plugin *fakeV1Plugin) credentialcomposer.CredentialComposer {
	server := credentialcomposerv1.CredentialComposerPluginServer(plugin)
	cc := new(credentialcomposer.V1)
	plugintest.Load(t, catalog.MakeBuiltIn("test", server), cc)
	return cc
}

type fakeV1Plugin struct {
	credentialcomposerv1.UnimplementedCredentialComposerServer

	err                                error
	composeServerX509CARequestIn       *credentialcomposerv1.ComposeServerX509CARequest
	composeServerX509CAResponseOut     *credentialcomposerv1.ComposeServerX509CAResponse
	composeServerX509SVIDRequestIn     *credentialcomposerv1.ComposeServerX509SVIDRequest
	composeServerX509SVIDResponseOut   *credentialcomposerv1.ComposeServerX509SVIDResponse
	composeAgentX509SVIDRequestIn      *credentialcomposerv1.ComposeAgentX509SVIDRequest
	composeAgentX509SVIDResponseOut    *credentialcomposerv1.ComposeAgentX509SVIDResponse
	composeWorkloadX509SVIDRequestIn   *credentialcomposerv1.ComposeWorkloadX509SVIDRequest
	composeWorkloadX509SVIDResponseOut *credentialcomposerv1.ComposeWorkloadX509SVIDResponse
	composeWorkloadJWTSVIDRequestIn    *credentialcomposerv1.ComposeWorkloadJWTSVIDRequest
	composeWorkloadJWTSVIDResponseOut  *credentialcomposerv1.ComposeWorkloadJWTSVIDResponse
}

func (p *fakeV1Plugin) ComposeServerX509CA(_ context.Context, req *credentialcomposerv1.ComposeServerX509CARequest) (*credentialcomposerv1.ComposeServerX509CAResponse, error) {
	p.composeServerX509CARequestIn = req
	return p.composeServerX509CAResponseOut, p.err
}

func (p *fakeV1Plugin) ComposeServerX509SVID(_ context.Context, req *credentialcomposerv1.ComposeServerX509SVIDRequest) (*credentialcomposerv1.ComposeServerX509SVIDResponse, error) {
	p.composeServerX509SVIDRequestIn = req
	return p.composeServerX509SVIDResponseOut, p.err
}

func (p *fakeV1Plugin) ComposeAgentX509SVID(_ context.Context, req *credentialcomposerv1.ComposeAgentX509SVIDRequest) (*credentialcomposerv1.ComposeAgentX509SVIDResponse, error) {
	p.composeAgentX509SVIDRequestIn = req
	return p.composeAgentX509SVIDResponseOut, p.err
}

func (p *fakeV1Plugin) ComposeWorkloadX509SVID(_ context.Context, req *credentialcomposerv1.ComposeWorkloadX509SVIDRequest) (*credentialcomposerv1.ComposeWorkloadX509SVIDResponse, error) {
	p.composeWorkloadX509SVIDRequestIn = req
	return p.composeWorkloadX509SVIDResponseOut, p.err
}

func (p *fakeV1Plugin) ComposeWorkloadJWTSVID(_ context.Context, req *credentialcomposerv1.ComposeWorkloadJWTSVIDRequest) (*credentialcomposerv1.ComposeWorkloadJWTSVIDResponse, error) {
	p.composeWorkloadJWTSVIDRequestIn = req
	return p.composeWorkloadJWTSVIDResponseOut, p.err
}

func makeOID(tb testing.TB, ids ...uint64) x509.OID {
	oid, err := x509.OIDFromInts(ids)
	require.NoError(tb, err)
	return oid
}
