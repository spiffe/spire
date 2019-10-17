package azure

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestMSITokenClaims(t *testing.T) {
	claims := MSITokenClaims{
		Claims: jwt.Claims{
			Subject: "PRINCIPALID",
		},
		TenantID: "TENANTID",
	}
	require.Equal(t, "spiffe://example.org/spire/agent/azure_msi/TENANTID/PRINCIPALID", claims.AgentID("example.org"))
}

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
			Body:       ioutil.NopCloser(strings.NewReader(body)),
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
			Body:       ioutil.NopCloser(strings.NewReader(body)),
		}, nil
	})
}
