package common

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/telemetry"

	"github.com/stretchr/testify/assert"
)

func TestSanitize(t *testing.T) {
	tests := []struct {
		desc   string
		in     string
		expect string
	}{
		{
			desc:   "unchanged",
			in:     "unchanged/\\-$^_s",
			expect: "unchanged/\\-$^_s",
		},
		{
			desc:   "spiffe",
			in:     "spiffe://something.something/something.else",
			expect: "spiffe://something_something/something_else",
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			out := SanitizeLabel(tt.in)

			assert.Equal(t, tt.expect, out)
		})
	}
}

func TestGetSanitizedLabel(t *testing.T) {
	labelName := "metric.name"

	tests := []struct {
		desc   string
		in     string
		expect string
	}{
		{
			desc:   "unchanged",
			in:     "unchanged/\\-$^_s",
			expect: "unchanged/\\-$^_s",
		},
		{
			desc:   "spiffe",
			in:     "spiffe://something.something/something.else",
			expect: "spiffe://something_something/something_else",
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			out := GetSanitizedLabel(labelName, tt.in)

			assert.Equal(t, telemetry.Label{Name: labelName, Value: tt.expect}, out)
		})
	}
}
