package httpchallenge

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateChallenge(t *testing.T) {
	tests := []struct {
		desc      string
		hostName  string
		agentName string
		nonce     string
		testNonce string
		expectErr string
	}{
		{
			desc:      "bad hostName",
			hostName:  "foo/bar",
			agentName: "ok",
			nonce:     "1234",
			testNonce: "1234",
			expectErr: "hostname can not contain a slash",
		},
		{
			desc:      "bad hostName",
			hostName:  "foo:bar",
			agentName: "ok",
			nonce:     "1234",
			testNonce: "1234",
			expectErr: "hostname can not contain a colon",
		},
		{
			desc:      "bad agentName",
			hostName:  "foo.bar",
			agentName: "not.ok",
			nonce:     "1234",
			testNonce: "1234",
			expectErr: "agentname can not contain a dot",
		},
		{
			desc:      "fail nonce",
			hostName:  "foo.bar",
			agentName: "ok",
			nonce:     "1234",
			testNonce: "1235",
			expectErr: "expected nonce \"1235\" but got \"1234\"",
		},
		{
			desc:      "success",
			hostName:  "foo.bar",
			agentName: "ok",
			nonce:     "1234",
			testNonce: "1234",
			expectErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			ad := &AttestationData{
				HostName:  tt.hostName,
				AgentName: tt.agentName,
				Port:      80,
			}
			c := &Challenge{
				Nonce: tt.testNonce,
			}

			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				_, err := res.Write([]byte(tt.nonce))
				require.NoError(t, err)
			}))
			defer func() { testServer.Close() }()

			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				if addr == "foo.bar:80" {
					addr = strings.TrimPrefix(testServer.URL, "http://")
				}
				dialer := &net.Dialer{}
				return dialer.DialContext(ctx, network, addr)
			}

			err := VerifyChallenge(context.Background(), &http.Client{Transport: transport}, ad, c)
			if tt.expectErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectErr)
				return
			}
			require.NoError(t, err)
		})
	}
}
