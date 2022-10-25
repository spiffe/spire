package azure

import (
	"context"
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
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestFetchMSIToken(t *testing.T) {
	ctx := context.Background()

	// unexpected status
	token, err := FetchMSIToken(ctx, fakeTokenHTTPClient(http.StatusBadRequest, "ERROR"), "RESOURCE")
	require.EqualError(t, err, "unexpected status code 400: ERROR")
	require.Empty(t, token)

	// empty response
	token, err = FetchMSIToken(ctx, fakeTokenHTTPClient(http.StatusOK, ""), "RESOURCE")
	require.EqualError(t, err, "unable to decode response: EOF")
	require.Empty(t, token)

	// malformed response
	token, err = FetchMSIToken(ctx, fakeTokenHTTPClient(http.StatusOK, "{"), "RESOURCE")
	require.EqualError(t, err, "unable to decode response: unexpected EOF")
	require.Empty(t, token)

	// no access token
	token, err = FetchMSIToken(ctx, fakeTokenHTTPClient(http.StatusOK, "{}"), "RESOURCE")
	require.EqualError(t, err, "response missing access token")
	require.Empty(t, token)

	// success
	token, err = FetchMSIToken(ctx, fakeTokenHTTPClient(http.StatusOK, `{"access_token": "ASDF"}`), "RESOURCE")
	require.NoError(t, err)
	require.Equal(t, "ASDF", token)
}

func TestFetchInstanceMetadata(t *testing.T) {
	ctx := context.Background()

	// unexpected status
	metadata, err := FetchInstanceMetadata(ctx, fakeMetadataHTTPClient(http.StatusBadRequest, "ERROR"))
	require.EqualError(t, err, "unexpected status code 400: ERROR")
	require.Nil(t, metadata)

	// empty response
	metadata, err = FetchInstanceMetadata(ctx, fakeMetadataHTTPClient(http.StatusOK, ""))
	require.EqualError(t, err, "unable to decode response: EOF")
	require.Nil(t, metadata)

	// malformed response
	metadata, err = FetchInstanceMetadata(ctx, fakeMetadataHTTPClient(http.StatusOK, "{"))
	require.EqualError(t, err, "unable to decode response: unexpected EOF")
	require.Nil(t, metadata)

	// no instance name
	metadata, err = FetchInstanceMetadata(ctx, fakeMetadataHTTPClient(http.StatusOK, `{
		"compute": {
			"subscriptionId": "SUBSCRIPTION",
			"resourceGroupName": "RESOURCEGROUP"
		}}`))
	require.EqualError(t, err, "response missing instance name")
	require.Nil(t, metadata)

	// no subscription id
	metadata, err = FetchInstanceMetadata(ctx, fakeMetadataHTTPClient(http.StatusOK, `{
		"compute": {
			"name": "NAME",
			"resourceGroupName": "RESOURCEGROUP"
		}}`))
	require.EqualError(t, err, "response missing instance subscription id")
	require.Nil(t, metadata)

	// no resource group name
	metadata, err = FetchInstanceMetadata(ctx, fakeMetadataHTTPClient(http.StatusOK, `{
		"compute": {
			"name": "NAME",
			"subscriptionId": "SUBSCRIPTION"
		}}`))
	require.EqualError(t, err, "response missing instance resource group name")
	require.Nil(t, metadata)

	// success
	expected := &InstanceMetadata{
		Compute: ComputeMetadata{
			Name:              "NAME",
			SubscriptionID:    "SUBSCRIPTION",
			ResourceGroupName: "RESOURCEGROUP",
		},
	}
	metadata, err = FetchInstanceMetadata(ctx, fakeMetadataHTTPClient(http.StatusOK, `{
		"compute": {
			"name": "NAME",
			"subscriptionId": "SUBSCRIPTION",
			"resourceGroupName": "RESOURCEGROUP"
		}}`))
	require.NoError(t, err)
	require.Equal(t, expected, metadata)
}

func TestMakeAgentID(t *testing.T) {
	type args struct {
		td                string
		agentPathTemplate string
		claims            *MSITokenClaims
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
				agentPathTemplate: "/{{ .PluginName }}/{{ .TenantID }}/{{ .PrincipalID }}",
				claims: &MSITokenClaims{
					Claims:      jwt.Claims{},
					TenantID:    "TENANTID",
					PrincipalID: "PRINCIPALID",
				},
			},
			want:      "spiffe://example.org/spire/agent/azure_msi/TENANTID/PRINCIPALID",
			errWanted: nil,
		},
		{
			name: "error applying template with non-existent field",
			args: args{
				td:                "example.org",
				agentPathTemplate: "/{{ .PluginName }}/{{ .TenantID }}/{{ .NonExistent }}",
				claims: &MSITokenClaims{
					Claims:      jwt.Claims{},
					TenantID:    "TENANTID",
					PrincipalID: "PRINCIPALID",
				},
			},
			want:      "",
			errWanted: errors.New("template: agent-path:1:38: executing \"agent-path\" at <.NonExistent>: can't evaluate field NonExistent in type azure.agentPathTemplateData"),
		},
		{
			name: "error building agent ID with invalid path",
			args: args{
				td:                "example.org",
				agentPathTemplate: "/{{ .PluginName }}/{{ .TenantID }}/{{ .PrincipalID }}",
				claims: &MSITokenClaims{
					Claims: jwt.Claims{},
				},
			},
			want:      "",
			errWanted: errors.New("invalid agent path suffix \"/azure_msi//\": path cannot contain empty segments"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			td := spiffeid.RequireTrustDomainFromString(test.args.td)
			agentPathTemplate, _ := agentpathtemplate.Parse(test.args.agentPathTemplate)
			got, err := MakeAgentID(td, agentPathTemplate, test.args.claims)
			if test.errWanted != nil {
				require.EqualError(t, err, test.errWanted.Error())
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, test.want, got.String())
		})
	}
}

func fakeTokenHTTPClient(statusCode int, body string) HTTPClient {
	return HTTPClientFunc(func(req *http.Request) (*http.Response, error) {
		// assert the expected request values
		if req.Method != "GET" {
			return nil, fmt.Errorf("unexpected method %q", req.Method)
		}
		if req.URL.Path != "/metadata/identity/oauth2/token" {
			return nil, fmt.Errorf("unexpected path %q", req.URL.Path)
		}
		if v := req.URL.Query().Get("api-version"); v != "2018-02-01" {
			return nil, fmt.Errorf("unexpected api version %q", v)
		}
		if v := req.URL.Query().Get("resource"); v != "RESOURCE" {
			return nil, fmt.Errorf("unexpected resource %q", v)
		}
		if v := req.Header.Get("metadata"); v != "true" {
			return nil, fmt.Errorf("unexpected metadata header %q", v)
		}

		// return the response
		return &http.Response{
			StatusCode: statusCode,
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})
}

func fakeMetadataHTTPClient(statusCode int, body string) HTTPClient {
	return HTTPClientFunc(func(req *http.Request) (*http.Response, error) {
		// assert the expected request values
		if req.Method != "GET" {
			return nil, fmt.Errorf("unexpected method %q", req.Method)
		}
		if req.URL.Path != "/metadata/instance" {
			return nil, fmt.Errorf("unexpected path %q", req.URL.Path)
		}
		if v := req.URL.Query().Get("api-version"); v != "2017-08-01" {
			return nil, fmt.Errorf("unexpected api version %q", v)
		}
		if v := req.Header.Get("metadata"); v != "true" {
			return nil, fmt.Errorf("unexpected metadata header %q", v)
		}

		// return the response
		return &http.Response{
			StatusCode: statusCode,
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})
}
