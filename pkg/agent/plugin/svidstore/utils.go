package svidstore

import (
	"fmt"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/proto/spire/agent/svidstore"
	"github.com/spiffe/spire/proto/spire/common"
)

type X509Response struct {
	SpiffeID string            `json:"spiffeID"`
	Key      []byte            `json:"key"`
	Svid     [][]byte          `json:"svid"`
	Bundles  map[string][]byte `json:"bundles"`
}

func X509ResponseFromProto(req *svidstore.PutX509SVIDRequest) (*X509Response, error) {
	td, err := spiffeid.TrustDomainFromString(req.Svid.SpiffeId)
	if err != nil {
		return nil, fmt.Errorf("failed to get trustdomain from SPIFFE ID: %w", err)
	}

	bundles := make(map[string][]byte)
	bundles[td.IDString()] = req.Svid.Bundle
	for id, bundle := range req.FederatedBundles {
		bundles[id] = bundle
	}

	resp := &X509Response{
		SpiffeID: req.Svid.SpiffeId,
		Key:      req.Svid.PrivateKey,
		Svid: [][]byte{
			req.Svid.CertChain,
		},
		Bundles: bundles,
	}

	return resp, nil
}

// ParseSelectors parses selectors for SVIDStore plugins
func ParseSelectors(pluginName string, selectors []*common.Selector) map[string]string {
	data := make(map[string]string)
	for _, s := range selectors {
		if s.Type != pluginName {
			continue
		}

		value := strings.Split(s.Value, ":")
		data[value[0]] = value[1]
	}

	return data
}
