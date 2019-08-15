package telemetry

import (
	"testing"

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
			in:     "sdkj25389",
			expect: "sdkj25389",
		},
		{
			desc:   "merge trailing replacement char",
			in:     "trailing/\\-$^_s",
			expect: "trailing_s",
		},
		{
			desc:   "spiffe",
			in:     "spiffe://something.something/something.else",
			expect: "spiffe_something_something_something_else",
		},
		// we shouldn't have timestamps in metrics, but we should
		// also protect ourselves against them
		{
			desc:   "timestamp",
			in:     "20190712 12:45:35.3548Z",
			expect: "20190712_12_45_35_3548Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			out := sanitizeLabel(tt.in)

			assert.Equal(t, tt.expect, out)
		})
	}
}

func TestGetSanitizedLabel(t *testing.T) {
	labelName := "metric.name"
	sanitizedLabelName := "metric_name"

	tests := []struct {
		desc   string
		in     string
		expect string
	}{
		{
			desc:   "unchanged",
			in:     "sdkj25389",
			expect: "sdkj25389",
		},
		{
			desc:   "merge trailing replacement char",
			in:     "trailing/\\-$^_s",
			expect: "trailing_s",
		},
		{
			desc:   "spiffe val",
			in:     "spiffe://something.something/something.else",
			expect: "spiffe_something_something_something_else",
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			out := getSanitizedLabel(labelName, tt.in)

			assert.Equal(t, Label{Name: sanitizedLabelName, Value: tt.expect}, out)
		})
	}
}

func TestGetSanitizedLabels(t *testing.T) {
	tests := []struct {
		desc   string
		in     []Label
		expect []Label
	}{
		{
			desc:   "nil in",
			in:     nil,
			expect: []Label{},
		},
		{
			desc:   "empty in",
			in:     []Label{},
			expect: []Label{},
		},
		{
			desc: "mix of cases",
			in: []Label{
				{
					Name:  "unchanged",
					Value: "sdkj25389",
				},
				{
					Name:  "trailing/_",
					Value: "trailing/\\-$^_s",
				},
				{
					Name:  "spiffe//.id",
					Value: "spiffe://something.something/something.else",
				},
			},
			expect: []Label{
				{
					Name:  "unchanged",
					Value: "sdkj25389",
				},
				{
					Name:  "trailing_",
					Value: "trailing_s",
				},
				{
					Name:  "spiffe_id",
					Value: "spiffe_something_something_something_else",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			out := GetSanitizedLabels(tt.in)

			assert.Equal(t, tt.expect, out)
		})
	}
}
