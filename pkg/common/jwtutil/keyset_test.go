package jwtutil

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	jose "gopkg.in/square/go-jose.v2"
)

func TestDiscoverKeySetURI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(jwksHandler))
	defer server.Close()

	// not found
	uri, err := DiscoverKeySetURI(context.Background(), server.URL+"/whatever")
	require.EqualError(t, err, "unexpected status code 404: not found\n")
	require.Equal(t, "", uri)

	// malformed response
	uri, err = DiscoverKeySetURI(context.Background(), server.URL+"/malformed")
	require.EqualError(t, err, "failed to decode configuration: unexpected EOF")
	require.Equal(t, "", uri)

	// no URL in response
	uri, err = DiscoverKeySetURI(context.Background(), server.URL+"/empty")
	require.EqualError(t, err, "configuration missing JWKS URI")
	require.Equal(t, "", uri)

	// success
	uri, err = DiscoverKeySetURI(context.Background(), server.URL+wellKnownOpenIdConfiguration)
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%s/keys", server.URL), uri)
}

func TestFetchKeySet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(jwksHandler))
	defer server.Close()

	// not found
	keySet, err := FetchKeySet(context.Background(), server.URL+"/whatever")
	require.EqualError(t, err, "unexpected status code 404: not found\n")
	require.Nil(t, keySet)

	// malformed response
	keySet, err = FetchKeySet(context.Background(), server.URL+"/malformed")
	require.EqualError(t, err, "failed to decode key set: unexpected EOF")
	require.Nil(t, keySet)

	// success
	keySet, err = FetchKeySet(context.Background(), server.URL+"/keys")
	require.NoError(t, err)
	require.NotNil(t, keySet)
	keys := keySet.Key("TioGywwlhvdFbXZ813WpPay9AlU")
	require.Len(t, keys, 1)
}

func TestOIDCIssuer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(jwksHandler))
	defer server.Close()

	// Other tests exercise the discovery functionality. This test simply
	// asserts that the URI for the OIDC server is crafted correctly.
	provider := OIDCIssuer(server.URL)
	keySet, err := provider.GetKeySet(context.Background())
	require.NoError(t, err)
	require.NotNil(t, keySet)
}

func TestCachingKeySetProvider(t *testing.T) {
	a := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "A"}}}
	b := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "B"}}}

	var providerJWKS *jose.JSONWebKeySet
	var providerErr error
	provider := func(ctx context.Context) (*jose.JSONWebKeySet, error) {
		return providerJWKS, providerErr
	}
	now := time.Now()

	// set up a new caching provider that refreshes every second
	caching := NewCachingKeySetProvider(KeySetProviderFunc(provider), time.Second)
	caching.hooks.now = func() time.Time {
		return now
	}

	// fail the first attempt to get the keyset. should return an error since
	// there is no keyset cached.
	providerErr = errors.New("FAILED")
	jwks, err := caching.GetKeySet(context.Background())
	require.EqualError(t, err, "FAILED")
	require.Nil(t, jwks)

	// assert that this attempt successfully returns keyset "a"
	providerErr = nil
	providerJWKS = a
	jwks, err = caching.GetKeySet(context.Background())
	require.NoError(t, err)
	require.Equal(t, a, jwks)

	// assert that this attempt continues to return keyset "a" since it has
	// been cached and the refresh interval has not elapsed
	providerErr = nil
	providerJWKS = b
	jwks, err = caching.GetKeySet(context.Background())
	require.NoError(t, err)
	require.Equal(t, a, jwks)

	// assert that this attempt continues to return keyset "a" since it has
	// been cached and the refresh interval has not elapsed
	providerErr = nil
	providerJWKS = b
	jwks, err = caching.GetKeySet(context.Background())
	require.NoError(t, err)
	require.Equal(t, a, jwks)

	// move forward past the refresh interval
	now = now.Add(time.Second)

	// assert that this attempt continues to return keyset "a" even though
	// the refresh interval has elapsed due to a failure from the wrapped
	// provider.
	providerErr = errors.New("FAILED")
	providerJWKS = b
	jwks, err = caching.GetKeySet(context.Background())
	require.NoError(t, err)
	require.Equal(t, a, jwks)

	// assert that this attempt returns keyset "b"
	providerErr = nil
	providerJWKS = b
	jwks, err = caching.GetKeySet(context.Background())
	require.NoError(t, err)
	require.Equal(t, b, jwks)
}

func jwksHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch req.URL.Path {
	case wellKnownOpenIdConfiguration:
		fmt.Fprintf(w, `{"jwks_uri":"http://%s/keys"}`, req.Host)
	case "/keys":
		fmt.Fprint(w, `{"keys":[{"kty":"RSA","use":"sig","kid":"TioGywwlhvdFbXZ813WpPay9AlU","x5t":"TioGywwlhvdFbXZ813WpPay9AlU","n":"vP3qtSGxB-MB7QlmeLsnmguri3_ebbsfBdKNk5Uz6YN80JDNMO8q-mbHr9UGYH5IB39wxz8Z-e1aX8NB5vTweCR3tQbNtXWtQ6zEfXmanAUAGNADmIVN3mLwGoxXPqy01VM_9ytLTpwowCibVWoCii5m_GLtVjyooXBZMGjwhLSmzfZ0ipjlen7q83LxZAYYSdV_kzHGtJKHHDrNMwzJfOgk-uvF73LSW4kX5zmtHLgRPY-Gkvqu2g2En4ShdpXTN0iNV6rZ5xIyhts_08G2oF2RBJEijhFj7NBkxMcX3NS7ZKkIqRvySriEhmSkZsSRqGg8gn8aVC2DqVuwRiimLw","e":"AQAB","x5c":["MIIDBTCCAe2gAwIBAgIQYbgOJ8Uror1IlEvjsPi7jzANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE4MDUxMTAwMDAwMFoXDTIwMDUxMTAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALz96rUhsQfjAe0JZni7J5oLq4t/3m27HwXSjZOVM+mDfNCQzTDvKvpmx6/VBmB+SAd/cMc/GfntWl/DQeb08Hgkd7UGzbV1rUOsxH15mpwFABjQA5iFTd5i8BqMVz6stNVTP/crS06cKMAom1VqAoouZvxi7VY8qKFwWTBo8IS0ps32dIqY5Xp+6vNy8WQGGEnVf5MxxrSShxw6zTMMyXzoJPrrxe9y0luJF+c5rRy4ET2PhpL6rtoNhJ+EoXaV0zdIjVeq2ecSMobbP9PBtqBdkQSRIo4RY+zQZMTHF9zUu2SpCKkb8kq4hIZkpGbEkahoPIJ/GlQtg6lbsEYopi8CAwEAAaMhMB8wHQYDVR0OBBYEFIwrggJsAwub9JGBkbpcqnwD052FMA0GCSqGSIb3DQEBCwUAA4IBAQAN9cz2xcZe76AxjQAOgaGGMrpowwmDht5ssS4SrwoL1gDvEP/pn4tTdYpPTP18EC7YMg925nbLmqNM0VJvO7AJr1I6G/HbmrCyyhvmZYZnAJVwqFwsPK2lJ1K0sjriL/g1UI0BofFsWBxBMqaDOp7+PTz27Ssn7UOo5ghKCMWaijNl+nsjfDtIJhKjISW8KduL5DO7Q+9R5ec/AyjheOCTmEij8V6nVBX642z9ujU9xOUaZZux9usuEHDhf7kqnOw/9/WyKluHoLhxFkTCV2Y12HabDtKo5iOP+ukjzNzZkRoo74Fi0tFB+nB24fdrd2TrxaGau/KXRu5QbXataOjz"]},{"kty":"RSA","use":"sig","kid":"7_Zuf1tvkwLxYaHS3q6lUjUYIGw","x5t":"7_Zuf1tvkwLxYaHS3q6lUjUYIGw","n":"vVzG98jfA-7UcUZkvrCdId9ypfoOW97MsXXBupSzr8NLkaHG28eTr72crI24KPOeQQqqXptMiCdRu9M-vRRQpreF7Or8P2eQa7ipfwtU41VaRvneaOc3jmWdV84uHpVDsnz_1S3_JtueFyfZrXa9aJHRzrz31OC1Gn6LRuRP11iX7f_B8_z5sGqaiXCejvKiO_8PEzPzqbOFLuVbqZL3PNi12zLogdwXY_1chpzZNo_R59SkutBjzXC5MTeBSHazqPu2o0ftoorY80C7Fe3Ia1n2v5uDSAysNddUonKVA72bhnknS-7PzGAISUuDe4k84jyr-PRist7msfLrsAKDQw","e":"AQAB","x5c":["MIIDBTCCAe2gAwIBAgIQE7nbxEiAlqhFdKnsKV+nuTANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE4MDYyMTAwMDAwMFoXDTIwMDYyMTAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL1cxvfI3wPu1HFGZL6wnSHfcqX6DlvezLF1wbqUs6/DS5GhxtvHk6+9nKyNuCjznkEKql6bTIgnUbvTPr0UUKa3hezq/D9nkGu4qX8LVONVWkb53mjnN45lnVfOLh6VQ7J8/9Ut/ybbnhcn2a12vWiR0c6899TgtRp+i0bkT9dYl+3/wfP8+bBqmolwno7yojv/DxMz86mzhS7lW6mS9zzYtdsy6IHcF2P9XIac2TaP0efUpLrQY81wuTE3gUh2s6j7tqNH7aKK2PNAuxXtyGtZ9r+bg0gMrDXXVKJylQO9m4Z5J0vuz8xgCElLg3uJPOI8q/j0YrLe5rHy67ACg0MCAwEAAaMhMB8wHQYDVR0OBBYEFDnSNW3pMmrshl3iBAS4OSLCu/7GMA0GCSqGSIb3DQEBCwUAA4IBAQAFs3C5sfXSfoi7ea62flYEukqyVMhrDrpxRlvIuXqL11g8KEXlk8pS8gEnRtU6NBeHhMrhYSuiqj7/2jUT1BR3zJ2bChEyEpIgOFaiTUxq6tXdpWi/M7ibf8O/1sUtjgYktwJlSL6FEVAMFH82TxCoTWp2g5i2lmZQ7KxiKhG+Vl9nw1bPX57hkWWhR7Hpes0MbpGNZI2IEpZSjNG1IWPPOBcaOh4ed2WBQcLcaTuAaELlaxanQaC0B3029To80MnzpZuadaul3+jN7JQg0MpHdJJ8GMHAWe/IjXc0evJNhVUcKON41hzTu0R+Sze7xq1zGljQihJgcNpO9oReBUsX"]},{"kty":"RSA","use":"sig","kid":"2S4SCVGs8Sg9LS6AqLIq6DpW-g8","x5t":"2S4SCVGs8Sg9LS6AqLIq6DpW-g8","n":"oZ-QQrNuB4ei9ATYrT61ebPtvwwYWnsrTpp4ISSp6niZYb92XM0oUTNgqd_C1vGN8J-y9wCbaJWkpBf46CjdZehrqczPhzhHau8WcRXocSB1u_tuZhv1ooAZ4bAcy79UkeLiG60HkuTNJJC8CfaTp1R97szBhuk0Vz5yt4r5SpfewIlBCnZUYwkDS172H9WapQu-3P2Qjh0l-JLyCkdrhvizZUk0atq5_AIDKRU-A0pRGc-EZhUL0LqUMz6c6M2s_4GnQaScv44A5iZUDD15B6e8Apb2yARohkWmOnmRcTVfes8EkfxjzZEzm3cNkvP0ogILyISHKlkzy2OmlU6iXw","e":"AQAB","x5c":["MIIDKDCCAhCgAwIBAgIQBHJvVNxP1oZO4HYKh+rypDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTYxMTE2MDgwMDAwWhcNMTgxMTE2MDgwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn5BCs24Hh6L0BNitPrV5s+2/DBhaeytOmnghJKnqeJlhv3ZczShRM2Cp38LW8Y3wn7L3AJtolaSkF/joKN1l6GupzM+HOEdq7xZxFehxIHW7+25mG/WigBnhsBzLv1SR4uIbrQeS5M0kkLwJ9pOnVH3uzMGG6TRXPnK3ivlKl97AiUEKdlRjCQNLXvYf1ZqlC77c/ZCOHSX4kvIKR2uG+LNlSTRq2rn8AgMpFT4DSlEZz4RmFQvQupQzPpzozaz/gadBpJy/jgDmJlQMPXkHp7wClvbIBGiGRaY6eZFxNV96zwSR/GPNkTObdw2S8/SiAgvIhIcqWTPLY6aVTqJfAgMBAAGjWDBWMFQGA1UdAQRNMEuAEDUj0BrjP0RTbmoRPTRMY3WhJTAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXOCEARyb1TcT9aGTuB2Cofq8qQwDQYJKoZIhvcNAQELBQADggEBAGnLhDHVz2gLDiu9L34V3ro/6xZDiSWhGyHcGqky7UlzQH3pT5so8iF5P0WzYqVtogPsyC2LPJYSTt2vmQugD4xlu/wbvMFLcV0hmNoTKCF1QTVtEQiAiy0Aq+eoF7Al5fV1S3Sune0uQHimuUFHCmUuF190MLcHcdWnPAmzIc8fv7quRUUsExXmxSX2ktUYQXzqFyIOSnDCuWFm6tpfK5JXS8fW5bpqTlrysXXz/OW/8NFGq/alfjrya4ojrOYLpunGriEtNPwK7hxj1AlCYEWaRHRXaUIW1ByoSff/6Y6+ZhXPUe0cDlNRt/qIz5aflwO7+W8baTS4O8m/icu7ItE="]}]}`)
	case "/malformed":
		fmt.Fprint(w, "{")
	case "/empty":
		fmt.Fprint(w, "{}")
	default:
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
}
