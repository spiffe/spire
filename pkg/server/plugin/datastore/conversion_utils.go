package datastore

import (
	"fmt"
	"net/url"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	datastorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/datastore/v1alpha1"
	ds_types "github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/protobuf/proto"
)

// This file contains utility functions for converting between types used in SPIRE server code
// and the wire types defined in the datastore v1alpha1 plugin SDK.
//
// These functions take the form of `fromServerToPluginX` or `fromPluginToServerX` to indicate
// which direction the conversion is going. Only required conversion functions should be implemented
// here.

func datastoreTypeConversionError[targetType any](err error, pluginType any) error {
	return fmt.Errorf("error converting between plugin type %T and server type %T: %w", pluginType, *new(targetType), err)
}

func serverTypeConversionError[targetType any](err error, serverType any) error {
	return fmt.Errorf("error converting between server type %T and plugin type %T: %w", serverType, *new(targetType), err)
}

func fromServerToPluginBundle(bundle *common.Bundle) (*datastorev1.Bundle, error) {
	if bundle == nil {
		return nil, nil
	}

	bundleBytes, err := proto.Marshal(bundle)
	if err != nil {
		return nil, serverTypeConversionError[*datastorev1.Bundle](err, bundle)
	}

	return &datastorev1.Bundle{
		Data:          bundleBytes,
		TrustDomainId: bundle.TrustDomainId,
	}, nil
}

func fromPluginToServerBundle(bundle *datastorev1.Bundle) (*common.Bundle, error) {
	if bundle == nil {
		return nil, nil
	}

	b := new(common.Bundle)
	if err := proto.Unmarshal(bundle.Data, b); err != nil {
		return nil, datastoreTypeConversionError[*common.Bundle](err, bundle)
	}

	return b, nil
}

func fromPluginToServerJwtSigningKey(datastoreJwtSigningKey *datastorev1.PublicKey) *common.PublicKey {
	if datastoreJwtSigningKey == nil {
		return nil
	}

	return &common.PublicKey{
		Kid:        datastoreJwtSigningKey.Kid,
		PkixBytes:  datastoreJwtSigningKey.PkixBytes,
		NotAfter:   datastoreJwtSigningKey.NotAfter,
		TaintedKey: datastoreJwtSigningKey.TaintedKey,
	}
}

func fromPluginToServerBundles(datastoreBundles []*datastorev1.Bundle) ([]*common.Bundle, error) {
	if datastoreBundles == nil {
		return nil, nil
	}

	commonBundles := make([]*common.Bundle, len(datastoreBundles))
	var err error
	for i, eachDatastoreBundle := range datastoreBundles {
		commonBundles[i], err = fromPluginToServerBundle(eachDatastoreBundle)
		if err != nil {
			return nil, err
		}
	}

	return commonBundles, nil
}

func fromPluginToServerPagination(datastorePagination *datastorev1.Pagination) *ds_types.Pagination {
	if datastorePagination == nil {
		return nil
	}

	return &ds_types.Pagination{
		PageSize: datastorePagination.PageSize,
		Token:    datastorePagination.PageToken,
	}
}

func fromServerToPluginPagination(pagination *ds_types.Pagination) *datastorev1.Pagination {
	if pagination == nil {
		return nil
	}

	return &datastorev1.Pagination{
		PageSize:  pagination.PageSize,
		PageToken: pagination.Token,
	}
}

func fromServerToPluginBundleMask(bundleMask *common.BundleMask) *datastorev1.BundleMask {
	if bundleMask == nil {
		return nil
	}

	return &datastorev1.BundleMask{
		RootCas:         bundleMask.RootCas,
		JwtSigningKeys:  bundleMask.JwtSigningKeys,
		SequenceNumber:  bundleMask.SequenceNumber,
		RefreshHint:     bundleMask.RefreshHint,
		WitSigningKeys:  bundleMask.WitSigningKeys,
		X509TaintedKeys: bundleMask.X509TaintedKeys,
	}
}

func fromServerToPluginDataConsistency(dataConsistency ds_types.DataConsistency) datastorev1.DataConsistency {
	switch dataConsistency {
	case ds_types.TolerateStale:
		return datastorev1.DataConsistency_DATA_CONSISTENCY_TOLERATE_STALE
	case ds_types.RequireCurrent:
		return datastorev1.DataConsistency_DATA_CONSISTENCY_REQUIRE_CURRENT
	default:
		return datastorev1.DataConsistency_DATA_CONSISTENCY_REQUIRE_CURRENT
	}
}

func fromPluginToServerSelector(dsSelector *datastorev1.Selector) *common.Selector {
	if dsSelector == nil {
		return nil
	}

	return &common.Selector{
		Type:  dsSelector.Type,
		Value: dsSelector.Value,
	}
}

func fromServerToPluginSelector(selector *common.Selector) *datastorev1.Selector {
	if selector == nil {
		return nil
	}

	return &datastorev1.Selector{
		Type:  selector.Type,
		Value: selector.Value,
	}
}

func fromPluginToServerSelectors(dsSelectors []*datastorev1.Selector) []*common.Selector {
	if dsSelectors == nil {
		return nil
	}

	commonSelectors := make([]*common.Selector, len(dsSelectors))
	for i, eachDsSelector := range dsSelectors {
		commonSelectors[i] = fromPluginToServerSelector(eachDsSelector)
	}

	return commonSelectors
}

func fromServerToPluginSelectors(selectors []*common.Selector) []*datastorev1.Selector {
	if selectors == nil {
		return nil
	}

	dsSelectors := make([]*datastorev1.Selector, len(selectors))
	for i, eachSelector := range selectors {
		dsSelectors[i] = fromServerToPluginSelector(eachSelector)
	}

	return dsSelectors
}

func fromServerToPluginBySelectors(sel *ds_types.BySelectors) *datastorev1.BySelectors {
	if sel == nil {
		return nil
	}

	selectors := make([]*datastorev1.Selector, len(sel.Selectors))
	for i, eachDsSelector := range sel.Selectors {
		selectors[i] = fromServerToPluginSelector(eachDsSelector)
	}

	return &datastorev1.BySelectors{
		Selectors:     selectors,
		MatchBehavior: datastorev1.MatchBehavior(sel.Match),
	}
}

func fromServerToPluginByFederatesWith(sel *ds_types.ByFederatesWith) *datastorev1.ByFederatesWith {
	if sel == nil {
		return nil
	}

	return &datastorev1.ByFederatesWith{
		FederatesWith: sel.TrustDomains,
		MatchBehavior: datastorev1.MatchBehavior(sel.Match),
	}
}

func fromServerToPluginRegistrationEntry(entry *common.RegistrationEntry) *datastorev1.RegistrationEntry {
	if entry == nil {
		return nil
	}

	return &datastorev1.RegistrationEntry{
		EntryId:        entry.EntryId,
		ParentId:       entry.ParentId,
		SpiffeId:       entry.SpiffeId,
		Selectors:      fromServerToPluginSelectors(entry.Selectors),
		FederatesWith:  entry.FederatesWith,
		Admin:          entry.Admin,
		DnsNames:       entry.DnsNames,
		X509SvidTtl:    entry.X509SvidTtl,
		JwtSvidTtl:     entry.JwtSvidTtl,
		Downstream:     entry.Downstream,
		StoreSvid:      entry.StoreSvid,
		EntryExpiry:    entry.EntryExpiry,
		Hint:           entry.Hint,
		CreatedAt:      entry.CreatedAt,
		RevisionNumber: entry.RevisionNumber,
	}
}

func fromPluginToServerRegistrationEntry(entry *datastorev1.RegistrationEntry) *common.RegistrationEntry {
	if entry == nil {
		return nil
	}

	return &common.RegistrationEntry{
		EntryId:        entry.EntryId,
		ParentId:       entry.ParentId,
		SpiffeId:       entry.SpiffeId,
		Selectors:      fromPluginToServerSelectors(entry.Selectors),
		FederatesWith:  entry.FederatesWith,
		Admin:          entry.Admin,
		DnsNames:       entry.DnsNames,
		X509SvidTtl:    entry.X509SvidTtl,
		JwtSvidTtl:     entry.JwtSvidTtl,
		Downstream:     entry.Downstream,
		StoreSvid:      entry.StoreSvid,
		EntryExpiry:    entry.EntryExpiry,
		Hint:           entry.Hint,
		CreatedAt:      entry.CreatedAt,
		RevisionNumber: entry.RevisionNumber,
	}
}

func fromPluginToServerRegisterationEntries(entries []*datastorev1.RegistrationEntry) []*common.RegistrationEntry {
	if entries == nil {
		return nil
	}

	commonEntries := make([]*common.RegistrationEntry, len(entries))
	for i, eachEntry := range entries {
		commonEntries[i] = fromPluginToServerRegistrationEntry(eachEntry)
	}

	return commonEntries
}

func fromServerToPluginRegistrationEntriesMask(mask *common.RegistrationEntryMask) *datastorev1.RegistrationEntryMask {
	if mask == nil {
		return nil
	}

	return &datastorev1.RegistrationEntryMask{
		ParentId:      mask.ParentId,
		SpiffeId:      mask.SpiffeId,
		Selectors:     mask.Selectors,
		FederatesWith: mask.FederatesWith,
		Admin:         mask.Admin,
		DnsNames:      mask.DnsNames,
		X509SvidTtl:   mask.X509SvidTtl,
		JwtSvidTtl:    mask.JwtSvidTtl,
		Downstream:    mask.Downstream,
		StoreSvid:     mask.StoreSvid,
		EntryExpiry:   mask.EntryExpiry,
		Hint:          mask.Hint,
	}
}

func fromServerToPluginFederationRelationship(fr *ds_types.FederationRelationship) (*datastorev1.FederationRelationship, error) {
	if fr == nil {
		return nil, nil
	}

	bundle, err := fromServerToPluginBundle(fr.TrustDomainBundle)
	if err != nil {
		return nil, err
	}
	bundleEndpointType, err := fromServerToPluginBundleEndpointType(fr.BundleEndpointProfile)
	if err != nil {
		return nil, err
	}
	rfr := &datastorev1.FederationRelationship{
		TrustDomainId:          fr.TrustDomain.IDString(),
		BundleEndpointSpiffeId: fr.EndpointSPIFFEID.String(),
		TrustDomainBundle:      bundle,
		BundleEndpointType:     bundleEndpointType,
	}

	if fr.BundleEndpointURL != nil {
		rfr.BundleEndpointUrl = fr.BundleEndpointURL.String()
	}

	return rfr, nil
}

func fromServerToPluginBundleEndpointType(bundleEndpointType ds_types.BundleEndpointType) (datastorev1.BundleEndpointType, error) {
	switch bundleEndpointType {
	case ds_types.BundleEndpointWeb:
		return datastorev1.BundleEndpointType_BUNDLE_ENDPOINT_TYPE_WEB, nil
	case ds_types.BundleEndpointSPIFFE:
		return datastorev1.BundleEndpointType_BUNDLE_ENDPOINT_TYPE_SPIFFE, nil
	default:
		return 0, fmt.Errorf("unknown bundle endpoint profile type: \"%v\"", bundleEndpointType) // TODO(tjons): we should make this a lot better, this is annoying
	}
}

func fromPluginToServerBundleEndpointType(bundleEndpointType datastorev1.BundleEndpointType) ds_types.BundleEndpointType {
	switch bundleEndpointType {
	case datastorev1.BundleEndpointType_BUNDLE_ENDPOINT_TYPE_WEB:
		return ds_types.BundleEndpointWeb
	case datastorev1.BundleEndpointType_BUNDLE_ENDPOINT_TYPE_SPIFFE:
		return ds_types.BundleEndpointSPIFFE
	default:
		return ds_types.BundleEndpointWeb
	}
}

func fromPluginToServerFederationRelationship(rfr *datastorev1.FederationRelationship) (*ds_types.FederationRelationship, error) {
	if rfr == nil {
		return nil, nil
	}

	url, err := url.Parse(rfr.BundleEndpointUrl)
	if err != nil {
		return nil, serverTypeConversionError[*ds_types.FederationRelationship](err, rfr)
	}
	bundle, err := fromPluginToServerBundle(rfr.TrustDomainBundle)
	if err != nil {
		return nil, err
	}

	var esi spiffeid.ID
	if rfr.BundleEndpointSpiffeId != "" {
		esi = spiffeid.RequireFromString(rfr.BundleEndpointSpiffeId)
	}

	fr := &ds_types.FederationRelationship{
		TrustDomain:           spiffeid.RequireTrustDomainFromString(rfr.TrustDomainId),
		EndpointSPIFFEID:      esi,
		BundleEndpointURL:     url,
		TrustDomainBundle:     bundle,
		BundleEndpointProfile: fromPluginToServerBundleEndpointType(rfr.BundleEndpointType),
	}

	return fr, nil
}

func fromServerToPluginCAJournal(caJournal *ds_types.CAJournal) *datastorev1.CAJournal {
	if caJournal == nil {
		return nil
	}

	return &datastorev1.CAJournal{
		Id:                    uint64(caJournal.ID),
		Data:                  caJournal.Data,
		ActiveX509AuthorityId: caJournal.ActiveX509AuthorityID,
	}
}

func fromPluginToServerCAJournal(caJournal *datastorev1.CAJournal) *ds_types.CAJournal {
	if caJournal == nil {
		return nil
	}

	return &ds_types.CAJournal{
		ID:                    uint(caJournal.Id),
		Data:                  caJournal.Data,
		ActiveX509AuthorityID: caJournal.ActiveX509AuthorityId,
	}
}

func fromPluginToServerAttestedNode(attestedNode *datastorev1.AttestedNode) *common.AttestedNode {
	if attestedNode == nil {
		return nil
	}

	return &common.AttestedNode{
		SpiffeId:            attestedNode.SpiffeId,
		AttestationDataType: attestedNode.AttestationDataType,
		CertSerialNumber:    attestedNode.CertSerialNumber,
		CertNotAfter:        attestedNode.CertNotAfter,
		NewCertSerialNumber: attestedNode.NewCertSerialNumber,
		NewCertNotAfter:     attestedNode.NewCertNotAfter,
		Selectors:           fromPluginToServerSelectors(attestedNode.Selectors),
		CanReattest:         attestedNode.CanReattest,
		AgentVersion:        attestedNode.AgentVersion,
	}
}

func fromServerToPluginAttestedNode(attestedNode *common.AttestedNode) *datastorev1.AttestedNode {
	if attestedNode == nil {
		return nil
	}

	return &datastorev1.AttestedNode{
		SpiffeId:            attestedNode.SpiffeId,
		AttestationDataType: attestedNode.AttestationDataType,
		CertSerialNumber:    attestedNode.CertSerialNumber,
		CertNotAfter:        attestedNode.CertNotAfter,
		NewCertSerialNumber: attestedNode.NewCertSerialNumber,
		NewCertNotAfter:     attestedNode.NewCertNotAfter,
		Selectors:           fromServerToPluginSelectors(attestedNode.Selectors),
		CanReattest:         attestedNode.CanReattest,
		AgentVersion:        attestedNode.AgentVersion,
	}
}

func fromServerToPluginDeleteMode(mode ds_types.DeleteMode) (datastorev1.DeleteMode, error) {
	switch mode {
	case ds_types.Delete:
		return datastorev1.DeleteMode_DELETE_MODE_DELETE, nil
	case ds_types.Restrict:
		return datastorev1.DeleteMode_DELETE_MODE_RESTRICT, nil
	case ds_types.Dissociate:
		return datastorev1.DeleteMode_DELETE_MODE_DISSOCIATE, nil
	}

	return 0, fmt.Errorf("invalid delete mode: %v", mode)
}
