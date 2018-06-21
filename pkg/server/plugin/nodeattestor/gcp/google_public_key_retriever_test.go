package gcp

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/require"
)

func TestGooglePublicKeyRetriever(t *testing.T) {
	require := require.New(t)

	expires := ""
	status := http.StatusOK
	body := ""

	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Expires", expires)
			w.WriteHeader(status)
			w.Write([]byte(body))
		}))
	defer server.Close()

	retriever := &googlePublicKeyRetriever{
		certificates: make(map[string]*x509.Certificate),
		url:          server.URL,
	}

	// token has no kid
	noKid := jwt.New(jwt.SigningMethodRS256)
	_, err := retriever.retrieveKey(noKid)
	require.EqualError(err, "token is missing kid value")

	// kid is not a string
	badKid := jwt.New(jwt.SigningMethodRS256)
	badKid.Header["kid"] = 3
	_, err = retriever.retrieveKey(badKid)
	require.EqualError(err, "token has unexpected kid value")

	// kid is empty
	emptyKid := jwt.New(jwt.SigningMethodRS256)
	emptyKid.Header["kid"] = ""
	_, err = retriever.retrieveKey(emptyKid)
	require.EqualError(err, "token has unexpected kid value")

	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = "7ddf54d3032d1f0d48c3618892ca74c1ac30ad77"

	// bad status
	status = http.StatusBadGateway
	_, err = retriever.retrieveKey(token)
	require.EqualError(err, "unexpected status code: 502")

	// malformed body
	status = http.StatusOK
	body = ""
	_, err = retriever.retrieveKey(token)
	require.EqualError(err, "unable to unmarshal certificate response: unexpected end of JSON input")

	// bad PEM block
	body = `{
		"badPEM": ""
}`
	_, err = retriever.retrieveKey(token)
	require.EqualError(err, "unable to unmarshal certificate response: malformed PEM block")

	// malformed certificate PEM
	body = `{
		"malformedCertPEM": "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"
}`
	_, err = retriever.retrieveKey(token)
	require.EqualError(err, "unable to unmarshal certificate response: malformed certificate PEM")

	// success
	expires = "Thu, 21 Jun 2018 01:53:33 GMT"
	body = `{
 "7ddf54d3032d1f0d48c3618892ca74c1ac30ad77": "-----BEGIN CERTIFICATE-----\nMIIDJjCCAg6gAwIBAgIILeRWqluroKYwDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE\nAxMrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAe\nFw0xODA2MTAxNDQ5MDhaFw0xODA2MjcwMzA0MDhaMDYxNDAyBgNVBAMTK2ZlZGVy\nYXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDIuVjK7H3j1vupL4N2pM2N1lvg22qI0f4m\n3sO1HGZ9b1dks5DpDY1iCY972HLLkYcbtbfOx3pD6vOrl4ZE0RTHXvrsrV1Lk+2R\nVY+I8b8zusOoK7cewuYpAqFGMdhoJaXk26IwHmZeg+FLCsd3bJ4YTtAchXv8KJAV\nzXFCxd6IL6dN4miEk7ccj3vDQZcTykeyktir2gbzt/kgfEWvz1pubBG6D4PtBZDJ\nblvh2h7hkv7nYn7xYd3naQasZ+7hDJXzegBp3cj/1D7KJY5dSv/QYivPPj/67keC\nph7Geh0WFllJoq5FKD9vmoKc+FbyAEMsAeSZDNAxpaw3XgvSmiRtAgMBAAGjODA2\nMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsG\nAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IBAQCogSpXj7bMqLHLafWUrzTQvbCFxs6M\nn3bhNjgZdvYuzaTotBhk1FI8hsszT7zh7euN6LLo/yf2qnr6yhch6YpRx4hux6cD\nShsPCML4ktcTNq1B+Q3BACDySA331AfcJKyPYvzwL+vi6656cntu0BhZ4+3KS+1R\nPOktwnRJLG9c6nLYkEyHy7ze4FT+eM/ML3hcZb20NHc1lP1XTwfbvyTwS7q19Afw\nOnvfOVsCPbIx8EdKenrsKnzgbPdswXbZkMifMvU/ky7Y2uKpuVlyb8yP2Qb3UsTM\nJh+1YTuprOIc7zhcvtr4ID+ax3hJgzenKWeCZWkvSLKZLHv2mdFd7AI4\n-----END CERTIFICATE-----\n",
 "dad44739576485ec30d228842e73ace0bc367bc4": "-----BEGIN CERTIFICATE-----\nMIIDJjCCAg6gAwIBAgIIS2LhfmO8/CkwDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE\nAxMrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAe\nFw0xODA2MTgxNDQ5MDhaFw0xODA3MDUwMzA0MDhaMDYxNDAyBgNVBAMTK2ZlZGVy\nYXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDT/x9qpZjjHwsJquI/q0huq3Zq1QzadIoC\n5Nvns1hlg4Z5Riji5oSEmMXqwnZ2M5J2mP5rvTMRqaGUcbIKyDM2uhBfvShovTnM\nvXBXRD1M8drWpGhtUNIGCWGYksd8RH0vSaT2OiRcmFakvs0VTurIoIPuDB7zg1Hg\nLt6Ze19AbMVLhVwqrE07Xu7CZErPH9kzLhK3330oQME8K26rxca+MxhkTZF+Tr4t\nZyYC0nsI45LXJ8R8CBu8IBsMqchmqiM+6yf/mNFQ6i0l3ZPcaCdIwQWfUbUMYruE\n0csEqrOKZ4QxNCmeFhds/CpNsACWXeu0pXg8IznzlBOxXRTdTlVpAgMBAAGjODA2\nMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsG\nAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IBAQCMJRcKLymRgqa7qvAqcNK5NerBpMn8\nBEz2J3jw8iuvEXo5tAqwOwzGR5YoM1EgH1F/MxNLnn6CGcpg+MV1rKTWP1aoWiu4\nBfzJngH0SPNDWWs9ZkYlaMnX0NK3d3zLMyUEx8PqTtazQLxK1FUJM3/KcyU77bt1\noUFGPua5/C6Kza/w2aQZSa7KRwgGGj+tjTtmXWVsEQcgWAiE4ZNDD/4cHrSYx3qk\nN/CVZRbq0t7fWXH8ezY3dTNptP9lqxyrfFLlRc5ddsBPuYSFeQ+wtxfR/+SD7WgD\njmifOam88PHhHbYbECt4n9b1OQg7lv0H8cm2/URjHAOP03CAYlb+t3UL\n-----END CERTIFICATE-----\n"
}`
	key, err := retriever.retrieveKey(token)
	require.NotNil(key)
	require.NoError(err)
	require.Equal("2018-06-21T01:53:33Z", retriever.expiry.Format(time.RFC3339))

	// uses cached values if not expired
	body = `{`
	key, err = retriever.retrieveKey(token)
	require.NotNil(key)
	require.NoError(err)
	require.Equal("2018-06-21T01:53:33Z", retriever.expiry.Format(time.RFC3339))

	// cache gets completely replaced when refreshed
	retriever.expiry = time.Now().Add(-time.Second)
	body = `{}`
	key, err = retriever.retrieveKey(token)
	require.Nil(key)
	require.EqualError(err, "no certificate found for kid")
}
