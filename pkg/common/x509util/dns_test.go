package x509util_test

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/stretchr/testify/assert"
)

func TestValidateDNS(t *testing.T) {
	tests := []struct {
		name string
		dns  string
		err  string
	}{
		{
			name: "empty dns",
			dns:  "",
			err:  "empty or only whitespace",
		},
		{
			name: "whitespace dns",
			dns:  " ",
			err:  "empty or only whitespace",
		},
		{
			name: "too long dns",
			dns: `BE3a7lf7WXVVf3ZyIJanGE7EhNxeAXEqCtSHXIxs3WRS5TXhmL1gzh2
KeW2wxmM5kVCi7KXYRha9iiULyrrzkL8mmaxdd05KoHwFuvSL7EUkWfhzzBQ65ZbK8VX
KpAxWdCD5cd2Vwzgz1ndMTt0aQUqfQiTvi0xXoe18ksShkOboNoEIWoaRoAwnSwbF01S
INk16I343I4FortWWCEV9nprutN3KQCZiIhHGkK4zQ6iyH7mTGc5bOfPIqE4aLynK`,
			err: "length exceeded",
		},
		{
			name: "dot only dns",
			dns:  ".",
			err:  "label is empty",
		},
		{
			name: "ending dot dns",
			dns:  "abcd.",
			err:  "label is empty",
		},
		{
			name: "too long label",
			dns:  "lFU37hAAULjx5LpB32MGe03GfrPqnQqLWBiWkkUYYJbIRBt7QlqahDbeshsd9JhP",
			err:  "label length exceeded: lFU37hAAULjx5LpB32MGe03GfrPqnQqLWBiWkkUYYJbIRBt7QlqahDbeshsd9JhP",
		},
		{
			name: "ending hyphen",
			dns:  "abc-",
			err:  "label does not match regex: abc-",
		},
		{
			name: "starting hyphen",
			dns:  "-abc",
			err:  "label does not match regex: -abc",
		},
		{
			name: "invalid character",
			dns:  "abc.df0f&",
			err:  "label does not match regex: df0f&",
		},
		{
			name: "consecutive hyphens",
			dns:  "abc.df--0f",
			err:  "",
		},
		{
			name: "series of hyphens",
			dns:  "abc.df--0------f",
			err:  "",
		},
		{
			name: "no hyphens",
			dns:  "abc.df0f.fa247d",
			err:  "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			err := x509util.ValidateDNS(tt.dns)

			if tt.err == "" {
				assert.NoError(t, err)
				return
			}
			assert.Contains(t, err.Error(), tt.err)
		})
	}
}
