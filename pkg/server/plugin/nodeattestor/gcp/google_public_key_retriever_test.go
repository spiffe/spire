package gcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

const (
	kid              = "7ddf54d3032d1f0d48c3618892ca74c1ac30ad77"
	publicKeyPayload = `{
 "7ddf54d3032d1f0d48c3618892ca74c1ac30ad77": "-----BEGIN CERTIFICATE-----\nMIIDJjCCAg6gAwIBAgIILeRWqluroKYwDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE\nAxMrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAe\nFw0xODA2MTAxNDQ5MDhaFw0xODA2MjcwMzA0MDhaMDYxNDAyBgNVBAMTK2ZlZGVy\nYXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDIuVjK7H3j1vupL4N2pM2N1lvg22qI0f4m\n3sO1HGZ9b1dks5DpDY1iCY972HLLkYcbtbfOx3pD6vOrl4ZE0RTHXvrsrV1Lk+2R\nVY+I8b8zusOoK7cewuYpAqFGMdhoJaXk26IwHmZeg+FLCsd3bJ4YTtAchXv8KJAV\nzXFCxd6IL6dN4miEk7ccj3vDQZcTykeyktir2gbzt/kgfEWvz1pubBG6D4PtBZDJ\nblvh2h7hkv7nYn7xYd3naQasZ+7hDJXzegBp3cj/1D7KJY5dSv/QYivPPj/67keC\nph7Geh0WFllJoq5FKD9vmoKc+FbyAEMsAeSZDNAxpaw3XgvSmiRtAgMBAAGjODA2\nMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsG\nAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IBAQCogSpXj7bMqLHLafWUrzTQvbCFxs6M\nn3bhNjgZdvYuzaTotBhk1FI8hsszT7zh7euN6LLo/yf2qnr6yhch6YpRx4hux6cD\nShsPCML4ktcTNq1B+Q3BACDySA331AfcJKyPYvzwL+vi6656cntu0BhZ4+3KS+1R\nPOktwnRJLG9c6nLYkEyHy7ze4FT+eM/ML3hcZb20NHc1lP1XTwfbvyTwS7q19Afw\nOnvfOVsCPbIx8EdKenrsKnzgbPdswXbZkMifMvU/ky7Y2uKpuVlyb8yP2Qb3UsTM\nJh+1YTuprOIc7zhcvtr4ID+ax3hJgzenKWeCZWkvSLKZLHv2mdFd7AI4\n-----END CERTIFICATE-----\n",
 "dad44739576485ec30d228842e73ace0bc367bc4": "-----BEGIN CERTIFICATE-----\nMIIDJjCCAg6gAwIBAgIIS2LhfmO8/CkwDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE\nAxMrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAe\nFw0xODA2MTgxNDQ5MDhaFw0xODA3MDUwMzA0MDhaMDYxNDAyBgNVBAMTK2ZlZGVy\nYXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDT/x9qpZjjHwsJquI/q0huq3Zq1QzadIoC\n5Nvns1hlg4Z5Riji5oSEmMXqwnZ2M5J2mP5rvTMRqaGUcbIKyDM2uhBfvShovTnM\nvXBXRD1M8drWpGhtUNIGCWGYksd8RH0vSaT2OiRcmFakvs0VTurIoIPuDB7zg1Hg\nLt6Ze19AbMVLhVwqrE07Xu7CZErPH9kzLhK3330oQME8K26rxca+MxhkTZF+Tr4t\nZyYC0nsI45LXJ8R8CBu8IBsMqchmqiM+6yf/mNFQ6i0l3ZPcaCdIwQWfUbUMYruE\n0csEqrOKZ4QxNCmeFhds/CpNsACWXeu0pXg8IznzlBOxXRTdTlVpAgMBAAGjODA2\nMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsG\nAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IBAQCMJRcKLymRgqa7qvAqcNK5NerBpMn8\nBEz2J3jw8iuvEXo5tAqwOwzGR5YoM1EgH1F/MxNLnn6CGcpg+MV1rKTWP1aoWiu4\nBfzJngH0SPNDWWs9ZkYlaMnX0NK3d3zLMyUEx8PqTtazQLxK1FUJM3/KcyU77bt1\noUFGPua5/C6Kza/w2aQZSa7KRwgGGj+tjTtmXWVsEQcgWAiE4ZNDD/4cHrSYx3qk\nN/CVZRbq0t7fWXH8ezY3dTNptP9lqxyrfFLlRc5ddsBPuYSFeQ+wtxfR/+SD7WgD\njmifOam88PHhHbYbECt4n9b1OQg7lv0H8cm2/URjHAOP03CAYlb+t3UL\n-----END CERTIFICATE-----\n"
}`
)

func TestGooglePublicKeyRetriever(t *testing.T) {
	suite.Run(t, new(GooglePublicKeyRetrieverSuite))
}

type GooglePublicKeyRetrieverSuite struct {
	suite.Suite
	server    *httptest.Server
	retriever *googlePublicKeyRetriever
	expires   string
	status    int
	body      string
}

func (s *GooglePublicKeyRetrieverSuite) SetupTest() {
	s.server = httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Expires", s.expires)
			w.WriteHeader(s.status)
			if _, err := w.Write([]byte(s.body)); err != nil {
				s.T().Logf("unable to write response body: %v", err)
			}
		}))
	s.retriever = newGooglePublicKeyRetriever(s.server.URL)
	s.status = http.StatusOK
	s.body = publicKeyPayload
}

func (s *GooglePublicKeyRetrieverSuite) TearDownTest() {
	s.server.Close()
}

func (s *GooglePublicKeyRetrieverSuite) TestUnexpectedStatusCode() {
	s.status = http.StatusBadGateway
	s.body = "{}"
	_, err := s.retriever.retrieveJWKS(context.Background())
	s.Require().EqualError(err, "unexpected status code: 502")
}

func (s *GooglePublicKeyRetrieverSuite) TestMalformedHTTPBody() {
	s.body = "{"
	_, err := s.retriever.retrieveJWKS(context.Background())
	s.Require().EqualError(err, "unable to unmarshal certificate response: unexpected EOF")
}

func (s *GooglePublicKeyRetrieverSuite) TestMalformedPEMBlock() {
	s.body = `{
		"someid": "NOT A PEM BLOCK"
	}`
	_, err := s.retriever.retrieveJWKS(context.Background())
	s.Require().EqualError(err, "unable to unmarshal certificate response: malformed PEM block")
}

func (s *GooglePublicKeyRetrieverSuite) TestMalformedCertificatePEM() {
	s.body = `{
		"malformedCertPEM": "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"
}`
	_, err := s.retriever.retrieveJWKS(context.Background())
	s.Require().EqualError(err, "unable to unmarshal certificate response: malformed certificate PEM")
}

func (s *GooglePublicKeyRetrieverSuite) TestSuccess() {
	s.body = publicKeyPayload
	s.expires = "Thu, 21 Jun 2018 01:53:33 UTC"

	jwks, err := s.retriever.retrieveJWKS(context.Background())
	s.Require().NoError(err)
	s.Require().NotEmpty(jwks.Key(kid))
	s.Require().Equal("2018-06-21T01:53:33Z", s.retriever.expiry.Format(time.RFC3339))
}

func (s *GooglePublicKeyRetrieverSuite) TestCacheUsedIfNotExpired() {
	// the endpoint will return a good body but since the cache is not
	// yet expired, the (empty) cache will be used.
	s.body = publicKeyPayload

	s.retriever.expiry = time.Now().Add(time.Minute)

	jwks, err := s.retriever.retrieveJWKS(context.Background())
	s.Require().NoError(err)
	s.Require().Empty(jwks.Key(kid))
}

func (s *GooglePublicKeyRetrieverSuite) TestCacheReplacedWhenRefreshed() {
	// first request primes the cache
	s.body = publicKeyPayload
	jwks, err := s.retriever.retrieveJWKS(context.Background())
	s.Require().NoError(err)
	s.Require().NotEmpty(jwks.Key(kid))

	// expire the cache
	s.retriever.expiry = time.Now().Add(-time.Minute)

	// cache contents should be replaced (with no certs)
	s.body = `{}`
	jwks, err = s.retriever.retrieveJWKS(context.Background())
	s.Require().NoError(err)
	s.Require().Empty(jwks.Key(kid))
}

func (s *GooglePublicKeyRetrieverSuite) TestFailToDownloadCertificates() {
	s.retriever.url = ""
	err := s.retriever.downloadJWKS(context.Background())
	s.requireErrorContains(err, "unsupported protocol scheme")
}

func (s *GooglePublicKeyRetrieverSuite) TestFailToReadCertificateBody() {
	s.server = httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			header := w.Header()
			header.Set("Expires", s.expires)
			// Write a non-zero content length but no body
			header.Set("Content-Length", "40")
			w.WriteHeader(http.StatusOK)
		}))
	s.retriever = newGooglePublicKeyRetriever(s.server.URL)
	err := s.retriever.downloadJWKS(context.Background())
	s.Require().EqualError(err, "unable to unmarshal certificate response: unexpected EOF")
}

func (s *GooglePublicKeyRetrieverSuite) requireErrorContains(err error, substring string) {
	s.Require().Error(err)
	s.Require().Contains(err.Error(), substring)
}
