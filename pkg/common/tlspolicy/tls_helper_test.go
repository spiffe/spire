package tlspolicy

import (
	"crypto/tls"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTLSVersion(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    uint16
		wantErr string
	}{
		{name: "VersionTLS12", in: "VersionTLS12", want: tls.VersionTLS12},
		{name: "VersionTLS13", in: "VersionTLS13", want: tls.VersionTLS13},
		{name: "empty defaults to TLS 1.2", in: "", want: tls.VersionTLS12},
		{name: "unknown", in: "VersionTLS99", wantErr: `unknown tls version "VersionTLS99"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TLSVersion(tt.in)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestDefaultTLSVersion(t *testing.T) {
	require.Equal(t, uint16(tls.VersionTLS12), DefaultTLSVersion())
}

func TestTLSCipherSuites(t *testing.T) {
	ecdheRSA := tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

	tests := []struct {
		name    string
		in      []string
		want    []uint16
		wantErr string
	}{
		{name: "empty", in: nil, want: nil},
		{
			name: "secure cipher",
			in:   []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			want: []uint16{ecdheRSA},
		},
		{
			name: "legacy chach20 rsa alias",
			in:   []string{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"},
			want: []uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256},
		},
		{
			name: "legacy chach20 ecdsa alias",
			in:   []string{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"},
			want: []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256},
		},
		{
			name:    "unknown cipher",
			in:      []string{"TLS_NOT_A_CIPHER"},
			wantErr: "Cipher suite TLS_NOT_A_CIPHER not supported or doesn't exist",
		},
		{
			name: "insecure cipher resolves",
			in:   []string{"TLS_ECDHE_RSA_WITH_RC4_128_SHA"},
			want: []uint16{tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TLSCipherSuites(tt.in)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestInsecureTLSCiphersReturnsCopy(t *testing.T) {
	got := InsecureTLSCiphers()
	require.NotEmpty(t, got)
	require.Contains(t, got, "TLS_ECDHE_RSA_WITH_RC4_128_SHA")

	got["TLS_ECDHE_RSA_WITH_RC4_128_SHA"] = 0
	require.NotEqual(t, uint16(0), insecureCiphers["TLS_ECDHE_RSA_WITH_RC4_128_SHA"])
}

func TestTLSCurvePreferences(t *testing.T) {
	tests := []struct {
		name    string
		in      []int32
		want    []tls.CurveID
		wantErr string
	}{
		{name: "empty", in: nil, want: nil},
		{
			name: "classical curves",
			in:   []int32{int32(tls.X25519), int32(tls.CurveP256)},
			want: []tls.CurveID{tls.X25519, tls.CurveP256},
		},
		{
			name: "hybrid ml-kem",
			in:   []int32{int32(tls.X25519MLKEM768)},
			want: []tls.CurveID{tls.X25519MLKEM768},
		},
		{
			name:    "duplicate",
			in:      []int32{int32(tls.X25519), int32(tls.X25519)},
			wantErr: "duplicate curve preference 29",
		},
		{
			name:    "zero out of range",
			in:      []int32{0},
			wantErr: "curve preference 0 is out of range (must be 1-65535)",
		},
		{
			name:    "negative out of range",
			in:      []int32{-1},
			wantErr: "curve preference -1 is out of range (must be 1-65535)",
		},
		{
			name:    "above uint16 out of range",
			in:      []int32{math.MaxInt32},
			wantErr: "curve preference 2147483647 is out of range (must be 1-65535)",
		},
		{
			name:    "unsupported curve id",
			in:      []int32{9999},
			wantErr: "curve preference 9999 is not supported by the current Go version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TLSCurvePreferences(tt.in)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
