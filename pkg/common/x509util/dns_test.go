package x509util_test

import (
	"errors"
	"testing"

	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/stretchr/testify/assert"
)

func FuzzValidateAndNormalize(f *testing.F) {
	f.Add("example.com")
	f.Add("*.example.com")
	f.Add("___.com")
	f.Fuzz(func(t *testing.T, domain string) {
		if err := x509util.ValidateLabel(domain); errors.Is(err, x509util.ErrLabelMismatchAfterIDNA) {
			t.Fatalf("domain: %q, err: %v", domain, err)
		}
	})
}

func TestValidateAndNormalize(t *testing.T) {
	tests := []struct {
		name    string
		dns     string
		wantErr error
	}{
		{
			name: "TLD",
			dns:  "com",
		},
		{
			name: "example.com",
			dns:  "example.com",
		},
		{
			name: "*.example.com",
			dns:  "*.example.com",
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
			name:    "emoji",
			dns:     "💩.com",
			wantErr: x509util.ErrNameMustBeASCII,
		},
		{
			name: "ascii puny code",
			dns:  "xn--ls8h.org",
		},
		{
			name:    "emoji tld",
			dns:     "example.💩",
			wantErr: x509util.ErrNameMustBeASCII,
		},
		{
			name: "hypen is ok",
			dns:  "a-hello.com",
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
			err := x509util.ValidateLabel(tc.dns)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestWildcardOverlap(t *testing.T) {
	tests := []struct {
		name    string
		dns     []string
		wantErr error
	}{
		{
			name: "no overlap",
			dns:  []string{"example.com", "*.example.com"},
		},
		{
			name:    "overlap",
			dns:     []string{"example.com", "*.example.com", "foo.example.com"},
			wantErr: x509util.ErrWildcardOverlap,
		},
		{
			name:    "overlap-flip",
			dns:     []string{"foo.example.com", "*.example.com", "example.com"},
			wantErr: x509util.ErrWildcardOverlap,
		},
		{
			name: "no overlap if subdomain",
			dns:  []string{"example.com", "*.example.com", "foo.bar.example.com"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := x509util.CheckForWildcardOverlap(tc.dns)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}
