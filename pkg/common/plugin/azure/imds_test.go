package azure

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchAttestedDocument(t *testing.T) {
	nonce := "TEST_NONCE"
	// unexpected status
	doc, err := FetchAttestedDocument(fakeAttestedDocumentHTTPClient(http.StatusBadRequest, "ERROR", nonce), nonce)
	require.EqualError(t, err, "unexpected status code 400: ERROR")
	require.Nil(t, doc)

	// empty response
	doc, err = FetchAttestedDocument(fakeAttestedDocumentHTTPClient(http.StatusOK, "", nonce), nonce)
	require.EqualError(t, err, "unable to decode response: EOF")
	require.Nil(t, doc)

	// malformed response
	doc, err = FetchAttestedDocument(fakeAttestedDocumentHTTPClient(http.StatusOK, "{", nonce), nonce)
	require.EqualError(t, err, "unable to decode response: unexpected EOF")
	require.Nil(t, doc)

	// no encoding
	doc, err = FetchAttestedDocument(fakeAttestedDocumentHTTPClient(http.StatusOK, `{"signature": "SIG"}`, nonce), nonce)
	require.EqualError(t, err, "response missing encoding")
	require.Nil(t, doc)

	// no signature
	doc, err = FetchAttestedDocument(fakeAttestedDocumentHTTPClient(http.StatusOK, `{"encoding": "base64"}`, nonce), nonce)
	require.EqualError(t, err, "response missing signature")
	require.Nil(t, doc)

	// mismatched nonce
	doc, err = FetchAttestedDocument(fakeAttestedDocumentHTTPClient(http.StatusOK, `{"encoding": "base64", "signature": "SIGNATURE"}`, "MISMATCHED_NONCE"), nonce)
	require.EqualError(t, err, "unexpected nonce \"TEST_NONCE\", expected \"MISMATCHED_NONCE\"")
	require.Nil(t, doc)

	// success
	expected := &AttestedDocument{
		Encoding:  "base64",
		Signature: "SIGNATURE",
	}
	doc, err = FetchAttestedDocument(fakeAttestedDocumentHTTPClient(http.StatusOK, `{"encoding": "base64", "signature": "SIGNATURE"}`, nonce), nonce)
	require.NoError(t, err)
	require.Equal(t, expected, doc)
}

func TestMakeIMDSAgentID(t *testing.T) {
	type args struct {
		td                string
		agentPathTemplate string
		data              *AttestedDocumentContent
	}
	tests := []struct {
		name      string
		args      args
		want      string
		errWanted error
	}{
		{
			name: "successfully applies template",
			args: args{
				td:                "example.org",
				agentPathTemplate: "/{{ .PluginName }}/{{ .TenantID }}/{{ .SubscriptionID }}/{{ .VMID }}",
				data: &AttestedDocumentContent{
					TenantID:       "TENANTID",
					SubscriptionID: "SUBSCRIPTIONID",
					VMID:           "VMID",
				},
			},
			want:      "spiffe://example.org/spire/agent/azure_imds/TENANTID/SUBSCRIPTIONID/VMID",
			errWanted: nil,
		},
		{
			name: "error applying template with non-existent field",
			args: args{
				td:                "example.org",
				agentPathTemplate: "/{{ .PluginName }}/{{ .TenantID }}/{{ .NonExistent }}",
				data: &AttestedDocumentContent{
					TenantID:       "TENANTID",
					SubscriptionID: "SUBSCRIPTIONID",
					VMID:           "VMID",
				},
			},
			want:      "",
			errWanted: errors.New("template: agent-path:1:38: executing \"agent-path\" at <.NonExistent>: can't evaluate field NonExistent in type azure.imdsAgentPathTemplateData"),
		},
		{
			name: "error building agent ID with invalid path",
			args: args{
				td:                "example.org",
				agentPathTemplate: "/{{ .PluginName }}/{{ .TenantID }}/{{ .SubscriptionID }}/{{ .VMID }}",
				data: &AttestedDocumentContent{
					TenantID:       "",
					SubscriptionID: "",
					VMID:           "",
				},
			},
			want:      "",
			errWanted: errors.New("invalid agent path suffix \"/azure_imds///\": path cannot contain empty segments"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			td := spiffeid.RequireTrustDomainFromString(test.args.td)
			agentPathTemplate, _ := agentpathtemplate.Parse(test.args.agentPathTemplate)
			got, err := MakeIMDSAgentID(td, agentPathTemplate, test.args.data)
			if test.errWanted != nil {
				require.EqualError(t, err, test.errWanted.Error())
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, test.want, got.String())
		})
	}
}

func fakeAttestedDocumentHTTPClient(statusCode int, body string, expectedNonce string) HTTPClient {
	return HTTPClientFunc(func(req *http.Request) (*http.Response, error) {
		// assert the expected request values
		if req.Method != "GET" {
			return nil, fmt.Errorf("unexpected method %q", req.Method)
		}
		if req.URL.Path != "/metadata/attested/document" {
			return nil, fmt.Errorf("unexpected path %q", req.URL.Path)
		}
		if v := req.URL.Query().Get("api-version"); v != "2025-04-07" {
			return nil, fmt.Errorf("unexpected api version %q", v)
		}
		if v := req.URL.Query().Get("nonce"); v != expectedNonce {
			return nil, fmt.Errorf("unexpected nonce %q, expected %q", v, expectedNonce)
		}
		if v := req.Header.Get("Metadata"); v != "true" {
			return nil, fmt.Errorf("unexpected metadata header %q", v)
		}

		// return the response
		return &http.Response{
			StatusCode: statusCode,
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})
}
