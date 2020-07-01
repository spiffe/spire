package api

import (
	"errors"
	"strings"

	"github.com/spiffe/spire/proto/spire-next/types"
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
