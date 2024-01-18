package x509util_test

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/stretchr/testify/assert"
)

func TestValidateAndNormalize(t *testing.T) {
	tests := []struct {
		name    string
		dns     string
		want    string
		wantErr error
	}{
		{
			name: "TLD",
			dns:  "com",
			want: "com",
		},
		{
			name: "example.com",
			dns:  "example.com",
			want: "example.com",
		},
		{
			name: "*.example.com",
			dns:  "*.example.com",
			want: "*.example.com",
		},
		{
			name:    ".",
			dns:     ".",
			wantErr: x509util.ErrDomainEndsWithDot,
		},
		{
			name:    "example.com.",
			dns:     "example.com.",
			wantErr: x509util.ErrDomainEndsWithDot,
		},
		{
			name:    "empty dns",
			dns:     "",
			wantErr: x509util.ErrEmptyDomain,
		},
		{
			name:    "too many wildcards",
			dns:     "*.foo.*.bar",
			wantErr: x509util.ErrTooManyWildcards,
		},
		{
			name:    "wildcard not in first label",
			dns:     "foo.*.bar",
			wantErr: x509util.ErrWildcardMustBeFirstLabel,
		},
		{
			name:    "whitespace dns",
			dns:     " ",
			wantErr: x509util.ErrEmptyDomain,
		},
		{
			name: "emoji",
			dns:  "💩.com",
			want: "xn--ls8h.com",
		},
		{
			name: "emoji tld",
			dns:  "example.💩",
			want: "example.xn--ls8h",
		},
		{
			name: "hypen is ok",
			dns:  "a-hello.com",
			want: "a-hello.com",
		},
		{
			name:    "starting hyphen is not ok",
			dns:     "-hello.com",
			wantErr: x509util.ErrIDNAError,
		},
		{
			name: "too long dns",
			dns: `BE3a7lf7WXVVf3ZyIJanGE7EhNxeAXEqCtSHXIxs3WRS5TXhmL1gzh2
KeW2wxmM5kVCi7KXYRha9iiULyrrzkL8mmaxdd05KoHwFuvSL7EUkWfhzzBQ65ZbK8VX
KpAxWdCD5cd2Vwzgz1ndMTt0aQUqfQiTvi0xXoe18ksShkOboNoEIWoaRoAwnSwbF01S
INk16I343I4FortWWCEV9nprutN3KQCZiIhHGkK4zQ6iyH7mTGc5bOfPIqE4aLynK`,
			wantErr: x509util.ErrIDNAError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := x509util.ValidateAndNormalize(tc.dns)
			assert.ErrorIs(t, err, tc.wantErr)
			assert.Equal(t, tc.want, result)
		})
	}
}
