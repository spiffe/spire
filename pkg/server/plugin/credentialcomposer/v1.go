package credentialcomposer

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	credentialcomposerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/credentialcomposer/v1"
	"github.com/spiffe/spire/pkg/common/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

var _ CredentialComposer = (*V1)(nil)

type V1 struct {
	plugin.Facade
	credentialcomposerv1.CredentialComposerPluginClient
}

func (v1 V1) ComposeServerX509CA(ctx context.Context, attributes X509CAAttributes) (X509CAAttributes, error) {
	attributesIn, err := x509CAAttributesToV1(attributes)
	if err != nil {
		return X509CAAttributes{}, v1.Errorf(codes.Internal, "invalid X509CA attributes: %v", err)
	}
	resp, err := v1.CredentialComposerPluginClient.ComposeServerX509CA(ctx, &credentialcomposerv1.ComposeServerX509CARequest{
		Attributes: attributesIn,
	})
	return v1.handleX509CAAttributesResponse(attributes, resp, err)
}

func (v1 V1) ComposeServerX509SVID(ctx context.Context, attributes X509SVIDAttributes) (X509SVIDAttributes, error) {
	attributesIn, err := x509SVIDAttributesToV1(attributes)
	if err != nil {
		return X509SVIDAttributes{}, v1.Errorf(codes.Internal, "invalid server X509SVID attributes: %v", err)
	}
	resp, err := v1.CredentialComposerPluginClient.ComposeServerX509SVID(ctx, &credentialcomposerv1.ComposeServerX509SVIDRequest{
		Attributes: attributesIn,
	})
	return v1.handleX509SVIDAttributesResponse(attributes, resp, err)
}

func (v1 V1) ComposeAgentX509SVID(ctx context.Context, id spiffeid.ID, publicKey crypto.PublicKey, attributes X509SVIDAttributes) (X509SVIDAttributes, error) {
	if id.IsZero() {
		return X509SVIDAttributes{}, v1.Error(codes.Internal, "invalid agent ID: empty")
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return X509SVIDAttributes{}, v1.Errorf(codes.Internal, "invalid agent X509SVID public key: %v", err)
	}

	attributesIn, err := x509SVIDAttributesToV1(attributes)
	if err != nil {
		return X509SVIDAttributes{}, v1.Errorf(codes.Internal, "invalid agent X509SVID attributes: %v", err)
	}
	resp, err := v1.CredentialComposerPluginClient.ComposeAgentX509SVID(ctx, &credentialcomposerv1.ComposeAgentX509SVIDRequest{
		Attributes: attributesIn,
		SpiffeId:   id.String(),
		PublicKey:  publicKeyBytes,
	})
	return v1.handleX509SVIDAttributesResponse(attributes, resp, err)
}

func (v1 V1) ComposeWorkloadX509SVID(ctx context.Context, id spiffeid.ID, publicKey crypto.PublicKey, attributes X509SVIDAttributes) (X509SVIDAttributes, error) {
	if id.IsZero() {
		return X509SVIDAttributes{}, v1.Error(codes.Internal, "invalid workload ID: empty")
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return X509SVIDAttributes{}, v1.Errorf(codes.Internal, "invalid workload X509SVID public key: %v", err)
	}

	attributesIn, err := x509SVIDAttributesToV1(attributes)
	if err != nil {
		return X509SVIDAttributes{}, v1.Errorf(codes.Internal, "invalid workload X509SVID attributes: %v", err)
	}
	resp, err := v1.CredentialComposerPluginClient.ComposeWorkloadX509SVID(ctx, &credentialcomposerv1.ComposeWorkloadX509SVIDRequest{
		Attributes: attributesIn,
		SpiffeId:   id.String(),
		PublicKey:  publicKeyBytes,
	})
	return v1.handleX509SVIDAttributesResponse(attributes, resp, err)
}

func (v1 V1) ComposeWorkloadJWTSVID(ctx context.Context, id spiffeid.ID, attributes JWTSVIDAttributes) (JWTSVIDAttributes, error) {
	if id.IsZero() {
		return JWTSVIDAttributes{}, v1.Error(codes.Internal, "invalid workload ID: empty")
	}
	attributesIn, err := jwtSVIDAttributesToV1(attributes)
	if err != nil {
		return JWTSVIDAttributes{}, v1.Errorf(codes.Internal, "invalid workload JWTSVID attributes: %v", err)
	}
	resp, err := v1.CredentialComposerPluginClient.ComposeWorkloadJWTSVID(ctx, &credentialcomposerv1.ComposeWorkloadJWTSVIDRequest{
		SpiffeId:   id.String(),
		Attributes: attributesIn,
	})
	return v1.handleJWTSVIDAttributesResponse(attributes, resp, err)
}

func (v1 V1) handleX509CAAttributesResponse(attributes X509CAAttributes, resp x509CAAttributesResponseV1, respErr error) (_ X509CAAttributes, err error) {
	if respErr != nil {
		if status.Code(respErr) == codes.Unimplemented {
			return attributes, nil
		}
		return X509CAAttributes{}, v1.WrapErr(respErr)
	}
	if pb := resp.GetAttributes(); pb != nil {
		attributes, err = x509CAAttributesFromV1(pb)
		if err != nil {
			return X509CAAttributes{}, v1.Errorf(codes.Internal, "plugin returned invalid X509CA attributes: %v", err)
		}
	}
	return attributes, nil
}

func (v1 V1) handleX509SVIDAttributesResponse(attributes X509SVIDAttributes, resp x509SVIDAttributesResponseV1, respErr error) (_ X509SVIDAttributes, err error) {
	if respErr != nil {
		if status.Code(respErr) == codes.Unimplemented {
			return attributes, nil
		}
		return X509SVIDAttributes{}, v1.WrapErr(respErr)
	}
	if pb := resp.GetAttributes(); pb != nil {
		attributes, err = x509SVIDAttributesFromV1(pb)
		if err != nil {
			return X509SVIDAttributes{}, v1.Errorf(codes.Internal, "plugin returned invalid X509SVID attributes: %v", err)
		}
	}
	return attributes, nil
}

func (v1 V1) handleJWTSVIDAttributesResponse(attributes JWTSVIDAttributes, resp jwtSVIDAttributesResponseV1, respErr error) (_ JWTSVIDAttributes, err error) {
	if respErr != nil {
		if status.Code(respErr) == codes.Unimplemented {
			return attributes, nil
		}
		return JWTSVIDAttributes{}, v1.WrapErr(respErr)
	}
	if pb := resp.GetAttributes(); pb != nil {
		attributes = jwtSVIDAttributesFromV1(pb)
	}
	return attributes, nil
}

func x509CAAttributesToV1(attributes X509CAAttributes) (*credentialcomposerv1.X509CAAttributes, error) {
	subject, err := subjectToV1(attributes.Subject)
	if err != nil {
		return nil, err
	}
	return &credentialcomposerv1.X509CAAttributes{
		Subject:           subject,
		PolicyIdentifiers: policyIdentifiersToV1(attributes.PolicyIdentifiers),
		ExtraExtensions:   extraExtensionsToV1(attributes.ExtraExtensions),
	}, nil
}

type x509CAAttributesResponseV1 interface {
	GetAttributes() *credentialcomposerv1.X509CAAttributes
}

func x509CAAttributesFromV1(pb *credentialcomposerv1.X509CAAttributes) (attributes X509CAAttributes, err error) {
	attributes.Subject, err = subjectFromV1(pb.Subject)
	if err != nil {
		return X509CAAttributes{}, fmt.Errorf("subject: %w", err)
	}
	attributes.PolicyIdentifiers, err = policyIdentifiersFromV1(pb.PolicyIdentifiers)
	if err != nil {
		return X509CAAttributes{}, fmt.Errorf("policy identifiers: %w", err)
	}
	attributes.ExtraExtensions, err = extraExtensionsFromV1(pb.ExtraExtensions)
	if err != nil {
		return X509CAAttributes{}, fmt.Errorf("extra extensions: %w", err)
	}
	return attributes, nil
}

type x509SVIDAttributesResponseV1 interface {
	GetAttributes() *credentialcomposerv1.X509SVIDAttributes
}

func x509SVIDAttributesToV1(attributes X509SVIDAttributes) (*credentialcomposerv1.X509SVIDAttributes, error) {
	subject, err := subjectToV1(attributes.Subject)
	if err != nil {
		return nil, err
	}
	return &credentialcomposerv1.X509SVIDAttributes{
		Subject:         subject,
		DnsSans:         attributes.DNSNames,
		ExtraExtensions: extraExtensionsToV1(attributes.ExtraExtensions),
	}, nil
}

func x509SVIDAttributesFromV1(pb *credentialcomposerv1.X509SVIDAttributes) (attributes X509SVIDAttributes, err error) {
	attributes.Subject, err = subjectFromV1(pb.Subject)
	if err != nil {
		return X509SVIDAttributes{}, fmt.Errorf("subject: %w", err)
	}
	attributes.DNSNames = pb.DnsSans
	attributes.ExtraExtensions, err = extraExtensionsFromV1(pb.ExtraExtensions)
	if err != nil {
		return X509SVIDAttributes{}, fmt.Errorf("extra extensions: %w", err)
	}
	return attributes, nil
}

type jwtSVIDAttributesResponseV1 interface {
	GetAttributes() *credentialcomposerv1.JWTSVIDAttributes
}

func jwtSVIDAttributesToV1(attributes JWTSVIDAttributes) (*credentialcomposerv1.JWTSVIDAttributes, error) {
	if len(attributes.Claims) == 0 {
		return nil, errors.New("invalid claims: cannot be empty")
	}
	// structpb.NewValue cannot handle Go types such as jwt.NumericDate so we marshal them into their JSON representation first
	jsonClaims, err := json.Marshal(attributes.Claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}
	claims := &structpb.Struct{}
	if err := claims.UnmarshalJSON(jsonClaims); err != nil {
		return nil, fmt.Errorf("failed to encode claims: %w", err)
	}
	return &credentialcomposerv1.JWTSVIDAttributes{
		Claims: claims,
	}, nil
}

func jwtSVIDAttributesFromV1(pb *credentialcomposerv1.JWTSVIDAttributes) JWTSVIDAttributes {
	return JWTSVIDAttributes{
		Claims: pb.Claims.AsMap(),
	}
}

func subjectFromV1(in *credentialcomposerv1.DistinguishedName) (pkix.Name, error) {
	if in == nil {
		return pkix.Name{}, errors.New("cannot be empty")
	}
	extraNames, err := extraNamesFromV1(in.ExtraNames)
	if err != nil {
		return pkix.Name{}, fmt.Errorf("extra names: %w", err)
	}
	return pkix.Name{
		Country:            in.Country,
		Organization:       in.Organization,
		OrganizationalUnit: in.OrganizationalUnit,
		Locality:           in.Locality,
		Province:           in.Province,
		StreetAddress:      in.StreetAddress,
		PostalCode:         in.PostalCode,
		SerialNumber:       in.SerialNumber,
		CommonName:         in.CommonName,
		ExtraNames:         extraNames,
	}, nil
}

func subjectToV1(in pkix.Name) (*credentialcomposerv1.DistinguishedName, error) {
	extraNames, err := extraNamesToV1(in.ExtraNames)
	if err != nil {
		return nil, err
	}
	return &credentialcomposerv1.DistinguishedName{
		Country:            in.Country,
		Organization:       in.Organization,
		OrganizationalUnit: in.OrganizationalUnit,
		Locality:           in.Locality,
		StreetAddress:      in.StreetAddress,
		PostalCode:         in.PostalCode,
		Province:           in.Province,
		SerialNumber:       in.SerialNumber,
		CommonName:         in.CommonName,
		ExtraNames:         extraNames,
	}, nil
}

func policyIdentifiersFromV1(ins []string) ([]asn1.ObjectIdentifier, error) {
	if ins == nil {
		return nil, nil
	}
	outs := make([]asn1.ObjectIdentifier, 0, len(ins))
	for _, in := range ins {
		out, err := parseOID(in)
		if err != nil {
			return nil, err
		}
		outs = append(outs, out)
	}
	return outs, nil
}

func policyIdentifiersToV1(ins []asn1.ObjectIdentifier) []string {
	if ins == nil {
		return nil
	}
	outs := make([]string, 0, len(ins))
	for _, in := range ins {
		outs = append(outs, in.String())
	}
	return outs
}

func extraExtensionsFromV1(ins []*credentialcomposerv1.X509Extension) ([]pkix.Extension, error) {
	if ins == nil {
		return nil, nil
	}
	outs := make([]pkix.Extension, 0, len(ins))
	for _, in := range ins {
		id, err := parseOID(in.Oid)
		if err != nil {
			return nil, err
		}
		outs = append(outs, pkix.Extension{
			Id:       id,
			Value:    in.Value,
			Critical: in.Critical,
		})
	}
	return outs, nil
}

func extraExtensionsToV1(ins []pkix.Extension) []*credentialcomposerv1.X509Extension {
	if ins == nil {
		return nil
	}
	outs := make([]*credentialcomposerv1.X509Extension, 0, len(ins))
	for _, in := range ins {
		outs = append(outs, &credentialcomposerv1.X509Extension{
			Oid:      in.Id.String(),
			Value:    in.Value,
			Critical: in.Critical,
		})
	}
	return outs
}

func extraNamesToV1(ins []pkix.AttributeTypeAndValue) ([]*credentialcomposerv1.AttributeTypeAndValue, error) {
	if ins == nil {
		return nil, nil
	}
	outs := make([]*credentialcomposerv1.AttributeTypeAndValue, 0, len(ins))
	for _, in := range ins {
		stringValue, ok := in.Value.(string)
		if !ok {
			return nil, errors.New("only string values are allowed in extra name attributes")
		}
		outs = append(outs, &credentialcomposerv1.AttributeTypeAndValue{
			Oid:         in.Type.String(),
			StringValue: stringValue,
		})
	}
	return outs, nil
}

func extraNamesFromV1(ins []*credentialcomposerv1.AttributeTypeAndValue) ([]pkix.AttributeTypeAndValue, error) {
	if ins == nil {
		return nil, nil
	}
	outs := make([]pkix.AttributeTypeAndValue, 0, len(ins))
	for _, in := range ins {
		typ, err := parseOID(in.Oid)
		if err != nil {
			return nil, err
		}
		outs = append(outs, pkix.AttributeTypeAndValue{
			Type:  typ,
			Value: in.StringValue,
		})
	}
	return outs, nil
}

func parseOID(s string) (_ asn1.ObjectIdentifier, err error) {
	parts := strings.Split(s, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, part := range parts {
		if oid[i], err = strconv.Atoi(part); err != nil {
			return nil, fmt.Errorf("invalid OID: non-integer part %q", part)
		}
	}
	return oid, nil
}
