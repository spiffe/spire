package api

import (
	"context"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// SelectorReferenceTypeURL is the canonical type URL of the SelectorReference
// WorkloadReference extension. A broker using this reference type supplies the
// selectors itself rather than naming something the agent can attest, so the
// agent accepts them as already attested.
const SelectorReferenceTypeURL = "type.googleapis.com/spiffe.broker.SelectorReference"

// DefaultMaxAssertedSelectors is the default ceiling on how many selectors a
// single SelectorReference may carry. It is generous enough for real callers
// (spire-identity-exchange presents on the order of 15-30 per request) while
// still bounding how much of the entry cache one request can sweep.
const DefaultMaxAssertedSelectors = 128

// selectorReferenceMessageName is the fully qualified protobuf message name of
// SelectorReference, i.e. "spiffe.broker.SelectorReference".
var selectorReferenceMessageName = string((&broker.SelectorReference{}).ProtoReflect().Descriptor().FullName())

// referenceMessageName returns the fully qualified protobuf message name from a
// protobuf type URL, which is everything after the last "/".
//
// Matching on the message name rather than the whole type URL is deliberate and
// security relevant: anypb only compares the segment after the final "/" when
// unmarshaling, so "example.com/spiffe.broker.SelectorReference" unmarshals into
// a SelectorReference just as the canonical URL does. A gate that compared raw
// type URL strings could therefore be bypassed with a non-canonical prefix.
func referenceMessageName(typeURL string) string {
	if i := strings.LastIndex(typeURL, "/"); i >= 0 {
		return typeURL[i+1:]
	}
	return typeURL
}

// isSelectorReference reports whether a type URL names a SelectorReference,
// tolerating non-canonical type URL prefixes.
func isSelectorReference(typeURL string) bool {
	return referenceMessageName(typeURL) == selectorReferenceMessageName
}

// requiresExplicitGrant reports whether a reference type must be named verbatim
// in a broker's allowed_reference_types, i.e. whether it is excluded from the
// "*" wildcard.
//
// The wildcard means "any reference type my attestor stack can resolve". A
// SelectorReference is resolved by nothing, so inheriting it from a wildcard
// would silently hand existing wildcard brokers a new and much stronger
// capability on agent upgrade.
func requiresExplicitGrant(typeURL string) bool {
	return isSelectorReference(typeURL)
}

// SelectorAssertionPolicy is the per-broker policy governing asserted
// selectors. It is only consulted for reference types that carry selectors.
type SelectorAssertionPolicy struct {
	// AllowedSelectorTypes is the set of selector types this broker may
	// assert. It is required and must be non-empty; an empty set denies
	// everything.
	AllowedSelectorTypes map[string]struct{}

	// MaxSelectors caps how many selectors a single reference may carry.
	MaxSelectors int
}

// selectorsFromSelectorReference resolves an asserted SelectorReference into
// selectors. Unlike the attested path it does not consult the workload
// attestor: the broker is the attestor, and the agent's job is to bound what it
// is allowed to assert.
func (s *Service) selectorsFromSelectorReference(ctx context.Context, log logrus.FieldLogger, caller spiffeid.ID, ref *anypb.Any) ([]*common.Selector, error) {
	var selRef broker.SelectorReference
	if err := anypb.UnmarshalTo(ref, &selRef, proto.UnmarshalOptions{}); err != nil {
		log.WithError(err).Error("Malformed selector reference")
		return nil, status.Errorf(codes.InvalidArgument, "malformed selector reference: %v", err)
	}

	// Fail closed. authorizeReferenceType already requires an explicit grant
	// for this reference type, so a missing policy here means the two config
	// maps disagree rather than that the caller is unrestricted.
	policy, ok := s.selectorAssertionByCaller[caller]
	if !ok {
		log.Error("Permission denied; broker is not configured to assert selectors")
		return nil, status.Errorf(codes.PermissionDenied, "broker %q is not configured to assert selectors", caller)
	}

	// Reject explicitly rather than letting an empty set fall through. An
	// empty selector set matches no cache records, which would otherwise
	// surface as an empty stream or a misleading "no identity issued".
	if len(selRef.Selectors) == 0 {
		log.Error("Invalid argument; selector reference contained no selectors")
		return nil, status.Error(codes.InvalidArgument, "selector reference must contain at least one selector")
	}

	maxSelectors := policy.MaxSelectors
	if maxSelectors <= 0 {
		maxSelectors = DefaultMaxAssertedSelectors
	}
	if len(selRef.Selectors) > maxSelectors {
		log.WithFields(logrus.Fields{
			"selector_count": len(selRef.Selectors),
			"max_selectors":  maxSelectors,
		}).Error("Invalid argument; too many asserted selectors")
		return nil, status.Errorf(codes.InvalidArgument, "selector reference contains %d selectors; at most %d are allowed", len(selRef.Selectors), maxSelectors)
	}

	// Reuse the Delegated Identity API's selector validation, which rejects an
	// empty type, an empty value, and a type containing ":".
	protoSelectors := make([]*types.Selector, 0, len(selRef.Selectors))
	for _, selector := range selRef.Selectors {
		protoSelectors = append(protoSelectors, &types.Selector{
			Type:  selector.GetType(),
			Value: selector.GetValue(),
		})
	}
	selectors, err := api.SelectorsFromProto(protoSelectors)
	if err != nil {
		log.WithError(err).Error("Invalid argument; could not parse provided selectors")
		return nil, status.Error(codes.InvalidArgument, "could not parse provided selectors")
	}

	// Enforce the per-broker selector type allowlist. Fail on the first
	// disallowed type so nothing is ever partially resolved.
	for _, selector := range selectors {
		if _, ok := policy.AllowedSelectorTypes[selector.Type]; !ok {
			log.WithField(telemetry.Type, selector.Type).Error("Permission denied; broker may not assert this selector type")
			return nil, status.Errorf(codes.PermissionDenied, "broker %q is not allowed to assert selector type %q", caller, selector.Type)
		}
	}

	// Audit at Info, not Debug. This is the only record that identities were
	// issued on the broker's word rather than on the agent's attestation, and
	// the workload attestor metrics do not cover this path.
	log.WithFields(logrus.Fields{
		telemetry.ReferenceType: SelectorReferenceTypeURL,
		telemetry.Selectors:     selectors,
		"selector_count":        len(selectors),
		"transport":             callerTransport(ctx),
	}).Info("Broker asserted selectors without attestation")

	return selectors, nil
}

// callerTransport describes the transport the caller connected over, for audit
// logging.
func callerTransport(ctx context.Context) string {
	if isTCPCaller(ctx) {
		return "tcp"
	}
	return "uds"
}
