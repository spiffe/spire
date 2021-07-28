package api

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/proto/spire/common"
)

// SelectorsFromProto converts a slice of types.Selector to
// a slice of common.Selector
func SelectorsFromProto(proto []*types.Selector) ([]*common.Selector, error) {
	var selectors []*common.Selector
	for _, s := range proto {
		switch {
		case s.Type == "":
			return nil, errors.New("missing selector type")
		case strings.Contains(s.Type, ":"):
			return nil, errors.New("selector type contains ':'")
		case s.Value == "":
			return nil, errors.New("missing selector value")
		}

		selectors = append(selectors, &common.Selector{
			Type:  s.Type,
			Value: s.Value,
		})
	}

	return selectors, nil
}

func ProtoFromSelectors(in []*common.Selector) []*types.Selector {
	var out []*types.Selector
	for _, s := range in {
		out = append(out, &types.Selector{
			Type:  s.Type,
			Value: s.Value,
		})
	}
	return out
}

func SelectorFieldFromProto(proto []*types.Selector) string {
	selectors := make([]string, 0, len(proto))
	for _, s := range proto {
		selectors = append(selectors, fmt.Sprintf("%s:%s", s.Type, s.Value))
	}

	return strings.Join(selectors, ",")
}
