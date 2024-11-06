package selector

import (
	"testing"

	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/assert"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name         string
		selectorType string
		err          bool
	}{
		{
			name:         "Type does not contain a colon",
			selectorType: "type",
		},
		{
			name:         "Type contains a colon",
			selectorType: "type:",
			err:          true,
		},
	}

	for _, test := range tests {
		test := test // alias loop variable as it is used in the closure
		t.Run(test.name, func(t *testing.T) {
			s := &common.Selector{
				Type: test.selectorType,
			}
			err := Validate(s)
			if test.err {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
