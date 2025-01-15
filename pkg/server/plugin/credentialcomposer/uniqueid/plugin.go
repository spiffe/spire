package uniqueid

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	credentialcomposerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/credentialcomposer/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func BuiltIn() catalog.BuiltIn {
	return builtIn(New())
}

func builtIn(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn("uniqueid",
		credentialcomposerv1.CredentialComposerPluginServer(p),
	)
}

type Plugin struct {
	credentialcomposerv1.UnsafeCredentialComposerServer
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) ComposeServerX509CA(context.Context, *credentialcomposerv1.ComposeServerX509CARequest) (*credentialcomposerv1.ComposeServerX509CAResponse, error) {
	// Intentionally not implemented.
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (p *Plugin) ComposeServerX509SVID(context.Context, *credentialcomposerv1.ComposeServerX509SVIDRequest) (*credentialcomposerv1.ComposeServerX509SVIDResponse, error) {
	// Intentionally not implemented.
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (p *Plugin) ComposeAgentX509SVID(context.Context, *credentialcomposerv1.ComposeAgentX509SVIDRequest) (*credentialcomposerv1.ComposeAgentX509SVIDResponse, error) {
	// Intentionally not implemented.
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (p *Plugin) ComposeWorkloadX509SVID(_ context.Context, req *credentialcomposerv1.ComposeWorkloadX509SVIDRequest) (*credentialcomposerv1.ComposeWorkloadX509SVIDResponse, error) {
	switch {
	case req.Attributes == nil:
		return nil, status.Error(codes.InvalidArgument, "request missing attributes")
	case req.SpiffeId == "":
		return nil, status.Error(codes.InvalidArgument, "request missing SPIFFE ID")
	}

	uniqueID, err := uniqueIDAttributeTypeAndValue(req.SpiffeId)
	if err != nil {
		return nil, err
	}

	// No need to clone
	attributes := req.Attributes
	if attributes.Subject == nil {
		attributes.Subject = &credentialcomposerv1.DistinguishedName{}
	}

	// Add the attribute if it does not already exist. Otherwise, replace the old value.
	found := false
	for i := range len(attributes.Subject.ExtraNames) {
		if attributes.Subject.ExtraNames[i].Oid == uniqueID.Oid {
			attributes.Subject.ExtraNames[i] = uniqueID
			found = true
			break
		}
	}
	if !found {
		attributes.Subject.ExtraNames = append(attributes.Subject.ExtraNames, uniqueID)
	}

	return &credentialcomposerv1.ComposeWorkloadX509SVIDResponse{
		Attributes: attributes,
	}, nil
}

func (p *Plugin) ComposeWorkloadJWTSVID(context.Context, *credentialcomposerv1.ComposeWorkloadJWTSVIDRequest) (*credentialcomposerv1.ComposeWorkloadJWTSVIDResponse, error) {
	// Intentionally not implemented.
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func uniqueIDAttributeTypeAndValue(id string) (*credentialcomposerv1.AttributeTypeAndValue, error) {
	spiffeID, err := spiffeid.FromString(id)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "malformed SPIFFE ID: %v", err)
	}

	uniqueID := x509svid.UniqueIDAttribute(spiffeID)

	oid := uniqueID.Type.String()
	stringValue, ok := uniqueID.Value.(string)
	if !ok {
		// purely defensive.
		return nil, status.Errorf(codes.Internal, "unique ID value is not a string")
	}

	return &credentialcomposerv1.AttributeTypeAndValue{
		Oid:         oid,
		StringValue: stringValue,
	}, nil
}
