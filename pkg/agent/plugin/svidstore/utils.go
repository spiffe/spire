package svidstore

import (
	"errors"
	"strings"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/spire/proto/spire/agent/svidstore"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/protobuf/proto"
)

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

// EncodeSecret creates a secrets binary from a 'workload.X509SVIDResponse'
func EncodeSecret(req *svidstore.PutX509SVIDRequest) ([]byte, error) {
	if req.Svid == nil {
		return nil, errors.New("request does not contains a SVID")
	}

	resp := &workload.X509SVIDResponse{
		Svids: []*workload.X509SVID{
			{
				SpiffeId:    req.Svid.SpiffeId,
				Bundle:      req.Svid.Bundle,
				X509Svid:    req.Svid.CertChain,
				X509SvidKey: req.Svid.PrivateKey,
			},
		},
		FederatedBundles: req.FederatedBundles,
	}
	return proto.Marshal(resp)
}
