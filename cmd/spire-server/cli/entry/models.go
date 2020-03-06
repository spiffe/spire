package entry

import (
	"strings"

	"github.com/spiffe/spire/proto/spire/common"
)

type Selector struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

type RegistrationEntry struct {
	Selectors     []*Selector `json:"selectors,omitempty"`
	ParentID      string      `json:"parent_id,omitempty"`
	SpiffeID      string      `json:"spiffe_id,omitempty"`
	TTL           int32       `json:"ttl,omitempty"`
	FederatesWith []string    `json:"federates_with,omitempty"`
	EntryID       string      `json:"entry_id,omitempty"`
	Admin         bool        `json:"admin,omitempty"`
	Downstream    bool        `json:"downstream,omitempty"`
	EntryExpiry   int64       `json:"entryExpiry,omitempty"`
	DNSNames      []string    `json:"dns_names,omitempty"`
	Type          string      `json:"type,omitempty"`
}

type RegistrationEntries struct {
	Entries []*RegistrationEntry `json:"entries,omitempty"`
}

func (s *Selector) ToProto() *common.Selector {
	return &common.Selector{
		Type:  s.Type,
		Value: s.Value,
	}
}

func (r *RegistrationEntry) ToProto() (*common.RegistrationEntry, error) {
	tUpper := strings.ToUpper(r.Type)
	t, err := RegistrationEntryTypeStringToProtoEnum(tUpper)
	if err != nil {
		return nil, err
	}

	var selectors []*common.Selector
	for _, s := range r.Selectors {
		selectors = append(selectors, s.ToProto())
	}

	return &common.RegistrationEntry{
		Selectors:     selectors,
		ParentId:      r.ParentID,
		SpiffeId:      r.SpiffeID,
		Ttl:           r.TTL,
		FederatesWith: r.FederatesWith,
		EntryId:       r.EntryID,
		Admin:         r.Admin,
		Downstream:    r.Downstream,
		EntryExpiry:   r.EntryExpiry,
		DnsNames:      r.DNSNames,
		Type:          t,
	}, nil
}

func (r *RegistrationEntries) ToProto() (*common.RegistrationEntries, error) {
	var protoRe []*common.RegistrationEntry
	for _, re := range r.Entries {
		protoReg, err := re.ToProto()
		if err != nil {
			return nil, err
		}

		protoRe = append(protoRe, protoReg)
	}

	return &common.RegistrationEntries{
		Entries: protoRe,
	}, nil
}
