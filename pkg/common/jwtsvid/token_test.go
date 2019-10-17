package jwtsvid

import (
	"context"
	"crypto"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	fakeSpiffeID = "spiffe://example.org/blog"
)

var (
	ctx           = context.Background()
	fakeAudience  = []string{"AUDIENCE"}
	fakeAudiences = []string{"AUDIENCE1", "AUDIENCE2"}

	ec256Key, _ = pemutil.ParseSigner([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgt/OIyb8Ossz/5bNk
XtnzFe1T2d0D9quX9Loi1O55b8yhRANCAATDe/2d6z+P095I3dIkocKr4b3zAy+1
qQDuoXqa8i3YOPk5fLib4ORzqD9NJFcrKjI+LLtipQe9yu/eY1K0yhBa
-----END PRIVATE KEY-----
`))

	ec384Key, _ = pemutil.ParseSigner([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgt/OIyb8Ossz/5bNk
XtnzFe1T2d0D9quX9Loi1O55b8yhRANCAATDe/2d6z+P095I3dIkocKr4b3zAy+1
qQDuoXqa8i3YOPk5fLib4ORzqD9NJFcrKjI+LLtipQe9yu/eY1K0yhBa
-----END PRIVATE KEY-----
`))

	rsa1024Key, _ = pemutil.ParseSigner([]byte(`-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMUJvNeDN6FBdRhu
sX40d+HbI1nREWQoq7YzSOwFfnGY9LGgvv2lHTbyBX2tusv80LuODbIMv54Cb+V5
vPT0yigXsOeRlaFq+YAlBte2uOoObL5ZoGagvkKQqP3to7MeGwrYx4e3eVYyKOk8
8GK5DLqu1fEROMx3qT30OY3gzIp5AgMBAAECgYAO19ny/j6NlknE6mnSkQ9K42A5
XueJfQraceiXZx6MXjJowyxAHVUjE35YZmMBBO2Qg3YCqLUyqQpW5iHW7i3gT3I4
tzeNm42Un5m4E+wfJKoyCuWEGlt+r7C3pPYTnymgA9uXTVYNcLV2fef0mo2+SajG
QgmWAUU6DE2gK/17FQJBAOpMiToLtS27W6l67YEAJlRNP3dLcWdQdnmRSzoPTEto
FQriFdSHHEwOCk6QMdM91qYt0ql48MGy4mw2qZODbxcCQQDXSbUfKQSa1AqZMFvJ
i5jNtL6osZ6wCdJa2A5/oxkH1gD6xRSAnSV7IvMVPhjPs11m0bWekQhP5yXjL7hm
60zvAkEA4lKwM/vfNZ/H+Tyfc377h29fIRMlJlFZQDETY7AnWKffu7WMtNEWinj9
h8pN9unDEJ8u4TnMBq+PfEyJHc9WXQJAGWLnqLT9hgRa+5VoPWvoqNkXYm0PeVKv
K2cuzn49BV+G3gs/T6s4MDz+zRJ1eoh8CxPPhtMzV7i6DwAhjoFQoQJAf0pfmmvl
ux9CEiQXFbCgnS4D78b6OZxjCacnPLbyOHouFF1WJuEu+4eHxfD5TMOCIBhTmbIu
Kzs/yXbmS2fezg==
-----END PRIVATE KEY-----
`))

	rsa2048Key, _ = pemutil.ParseSigner([]byte(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDJtODbX0oFZxYe
xruMjDS2CxNHTtmRzKXwi0oKemLgceePM5+jwWHm7XwHAAR920PYzzMYOZfp6QWp
h8CjxscwBMuAE0bXjUXsQAlu/6bZtT2JClyVVZ2VaciPw2nLOZ81s0zRx2uEnfaf
SXCbChYsDWeqo7tfOGOIgH1ieiZL/ZSEvNzQnlVI9Wk0b4V2xNQMPgXMbvlYZXZR
h4DoX6vKZMx+L0p5X6fsabSVDZm0pvNERZ/LZV57apGqxID2Knm8LtSG4ENmoFoq
styN84VX6QazeiUdKZzwLWxjBFHMnrTI69CwUg9PRp0V3A+m7Jj3fY4lQh9ctnrP
KXwq7lD3AgMBAAECggEAecJHTgVqgHJnBvL+OexU0WNEIvJ1Ia8AqIDclBCm6Ue4
+Ve3UTmmKKlJCky3aWXXwePpuwDhNCEm+txorDSM/u6WDV0VkX7FK8TILQoEJT1j
xPrNQpQpCQ2PNUFH9pZ1BgyTHbscqzRTsHm7kMt48OSypG4r6GH4q2isx6pmvc1k
EiuaWPxYYf8rNn9rlz4qnl+3uJRKP7tALXy72SRk3k5BgYlUZggTMEnuIkJmdNGS
fnIPVq5c7FA7NZriENSwXNz2Bh46KUyaXNApRJUKRV5BnqOKXYv2StiO2RHHxo3r
IhPA1VjjwclSqPMq/bzXfkGzjtr+x+RVdIvc4anSEQKBgQDKdv+i5HZsTyzW3qbr
7AJJE9D/Cq0p29L+ySaP/s8xPrVGA7DfkK3AAlIDc+nzkwmzPAXr3YS4igDkPACl
qbAQXoWpClTLrsU74M145/13kK6Z1zEYzOVVcrpUQWP2Vzr8kVR548wPQfRqrx/U
psLvgnEnC5H2SdsyX/oF5JdV7wKBgQD/Co0ScglsNlXxT/mZBsqh7RR7miXcK29t
TBoJMusUUYRQJIcC9MedYP2Djy6UkUp6L+mgclda64yPMdVWRPXe9CLEfJ1GKosX
6Xl3Dnj7n9eZk27+f1Jkwnu/fL2iFmqWXgX2MuqKLZQe6KlZMe0L4XtoZb0KRbfR
y6DZ1Z99eQKBgFr7AoEmfPjK03Fy+DuIALbqCr6xA4ON3tDTf1qxvFV6wmbF/dNY
5lskL8qRag4kgvViAZ8uGhf7G890Dy5ihFW2xAVkORqWXNc9e9fbGBGEmJFVHCDy
4hN1zLlT8SGfrUgV3oovjWFF2BmgvIMItQx/520OS/cK1U9bxbSkNkVNAoGBAKQh
Zig4u1eooCZsEXUpqb4LlOL2kObgDRWJpDfHTQIGc+AfocOFQ/FEOeIwgwmZdxSr
QO7ApvccH5kHuQOL3a9d7gIFMDG3r0v0NPcpmTJV66op94RQ6/VsM7dHz8JAKtga
KjwHCGlka654jIOaXbMHqSPGVaIGvAWHxjxp/foBAoGABhNVLoJLruWDdbINGGCs
6P5XKzxTuHwwL3i/g03DUfUW3xwo+wQBC+XepHSkIdvtg2pCKswCZlmoQ/GGh7Q4
nS8XeqNZQ30iT7lHopFA4qwTcK/a7CfA9rG3qXA+wcVBfb45pTzofXTXNSj/o+K9
GskWlRzafCDf6OElQz9PsmE=
-----END PRIVATE KEY-----
`))
	rsa4096Key, _ = pemutil.ParseSigner([]byte(`-----BEGIN PRIVATE KEY-----
MIIHCgIBADANBgkqhkiG9w0BAQEFAASCBvQwggbwAgEAAoIBhADGFH2zF3QbUJVu
GbbJjf3uN/NLCeGUlyKsClTtoF3yFZxHv9oajO1rRA7UnhyjsWJnJRO1kNaGMTWZ
Vl4c9hY/Q1AELWyXNJAdFsglarcz6PuWwwbdcmyh2B7VxMlPnmhXc3A0X4/miNR6
3/leU/zT3lrMFK9ZkvsdmjUv12zYz2woDe9WIm3HpEX4m3bwmpisq8lDEVoKgLrK
sd6opJD8/6GIs1GCshr8nPqPBhSqn1IryZLaPPD65NhZP98u0vM7x3byPM/SD0mC
lMED5DkpdD+8DTRJJY1+qUKehKzfVlnO+1B2Pp+FfufvFwxDM0TL0yAkAPp58P6D
MI4TMXUSvezXNvGQNY5Yfk3sKNkhj3UFxg6ZH6aS/El6PKNMFsXdgocg3yIyDAQO
Cu8JpyR6suBMSgYufA4qsIfzDw6oh5qp+w5A+xW1oP9iTUKbITE1C9+TPUXXW4XN
cB78j7YHzvW5dtaYRYST38kByuGFRlZdchUvB+uh8j8yjcCG32n59ycCAwEAAQKC
AYNoDkOqXVvFLaQSXrfDUjBfgEzy0pIKeQrhzdunqWMw1WFv3703zWi7vNj9oMHy
zDChdrzP2PKZNCiwEMsH887kFPxn9WTiWd6LKXijD1iGkJH6NSHaG04uB1bLfcEz
bkfqCN6c5Ma3mJHmqtpZT022D00rgIJNUAVTG7ttEoI/s1diA1ADs7pv8kA/xYvK
AazKqMPl06u1cMKv0JjjhvATuEanhWwAeIfsxJproAojR+bm0dGvi+wcITP2TrNz
6aWVZvELfTre5vcVfYdwQQlOP0W0YA/NiqvPFSJMe5yoPVIBzKV8ORfqEhAbY4t6
QdmCew0rSsZRHMbZRBJf7ziO7r/Og1/I7wFhcD/QxvWuuYlUPKWeasp4M7/f4G2x
7XstW2O/qHgJxbnytgHN9nZirMYsL3Cj00r7LbqDWok6HbrogM4++TV4uRIfZqBz
V4HXBgRApTMJoAjqpmpe00asdMVMp0A0VnMQbK6qJCnPTbITxMqbGmnkbhKwPCZk
kWzlP6ECgcIPSW54Uc6HCA+Wq3LLc9it3B0sQP9kCDcR1vNka607fU0bRrLgjnq/
PaPY3fuRuRWA3rAfbIJogGCDljrB/hRqRlHvZ2STb3lRGTDeyRyhZ0rB3Z7e6cR2
VixFjMCtU1XEmM19LIr5lxxAa6sA83wqTJHHWP/BAZ/W2A5Au+LDjAPH/n3SqaJO
+lUSMLJhlxpMjHbPs0cac/K5EKijNP65YLZNPABadYEiT3V8FZhqqMueuHvNbPCg
SBEh/A/2UGOFgwKBwgz1IhqFmOs581R7PuIIGCtWiUWhPo3YueNBa8nXlB+4+IBM
zEVwKsR3qP8Du8xZFjWV9ysJwlRLK4wTJlIxncFxLn6qpdPVhYxQxZbuN+plEr6E
1KeGBvWbHl+u7m7pc8t8U7VNaIJDH0xtgjhY13yky0YNvAqPwEsst9ONxzskOegO
9f4+MnFRdWLO2nE4Qpq3U3E0G5QQb7vOqwePKl8BS//lwfSUxwQIUwfy1VW75R12
7zaIGaFEch98ewQ3A3qNAoHCBKhqSa0bkddp8I3jF4z/69HS7cYMS22ZYg0t8l5A
1YyTbwk2veeMDTN59j2FRtyvaanw3lJQ1giv38hptOx3Sf6NPrYxVh80Rvq3Alsj
JybzB2lA3Ek8fJY7PSHrH6Tx0EqC6m4lFnHtwM9Ntqd6IOVd0fETVLrq+iqxBRZ6
vPyvtkOcERFxDEGIpFdEMyo4cDSoixbkRnIn9i3WRIyERPXr9lKfBPEi3NJ7SMjH
vVAbYwxxZKGaHCx5U/Ka5oGOIYMCgcIKAri+VMi3sqXTdwQ2DJrfoJOdP93cKLw0
Xq6v2eWOPJGATdTjMK1Z7DicDH5iedE2xQ2YKooAJbMXHRRWHA8NDCwnoB9NcYEj
zqNY3+JDLKM2ndjNNDbcOWNV+QgsmB/l7b+eKpe7S7A6k8AvWDPjEE4baTEF19lw
OrQqtTZe8rXqGuTh75t5AL34AGezYQvUDB5jLya/VZN9PUXVKT5K9+2HXjJiiy7W
Zrf/RBSdj/SKtwBI2Q00EnU47ir8LqR5YQKBwgIogvDOVcYTksPkCOwVh8Az0Qux
LSnTCadkU+Mh2CYEaF/1dnFdIyXvLUUVLc6Ac/qnT0k5a7G+noF0XDnh8i7gxu3J
3J9yy+6HJdo1tx6vGBqr6gh32Ix8MxhamFj7c4H5chxpay57qz9wwFghnA0i0hB0
tB9gAFps/Ka31SEZAg/GJxZuxIUzXRq5M73Y6wijos/xi8AMNpzHSSwsRid5R+Oq
96A646vR3voz0WAoWGHE5oCYb+uoCYbWG/pnFHVC
-----END PRIVATE KEY-----
`))
)

func TestToken(t *testing.T) {
	spiretest.Run(t, new(TokenSuite))
}

type TokenSuite struct {
	spiretest.Suite

	bundle KeyStore
	signer *Signer
}

func (s *TokenSuite) SetupTest() {
	s.bundle = NewKeyStore(map[string]map[string]crypto.PublicKey{
		"spiffe://example.org": {
			"ec256Key":   ec256Key.Public(),
			"ec384Key":   ec384Key.Public(),
			"rsa1024Key": rsa1024Key.Public(),
			"rsa2048Key": rsa2048Key.Public(),
			"rsa4096Key": rsa4096Key.Public(),
		},
	})
	s.signer = NewSigner(SignerConfig{
		Clock: clock.NewMock(s.T()),
	})
}

func (s *TokenSuite) TestSignAndValidate() {
	testCases := []struct {
		kid     string
		key     crypto.Signer
		signErr string
	}{
		{
			kid: "ec256Key",
			key: ec256Key,
		},
		{
			kid: "ec384Key",
			key: ec384Key,
		},
		{
			kid:     "rsa1024Key",
			key:     rsa1024Key,
			signErr: "unsupported RSA key size: 128",
		},
		{
			kid: "rsa2048Key",
			key: rsa2048Key,
		},
		{
			kid: "rsa4096Key",
			key: rsa4096Key,
		},
	}

	for _, testCase := range testCases {
		s.T().Run(testCase.kid, func(t *testing.T) {
			token, err := s.signer.SignToken(fakeSpiffeID, fakeAudience, time.Now().Add(time.Hour), testCase.key, testCase.kid)
			if testCase.signErr != "" {
				require.EqualError(t, err, testCase.signErr)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, token)

			spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, fakeAudience[0:1])
			require.NoError(t, err)
			require.Equal(t, fakeSpiffeID, spiffeID)
			require.NotEmpty(t, claims)
		})
	}
}

func (s *TokenSuite) TestSignAndValidateWithAudienceList() {
	token, err := s.signer.SignToken(fakeSpiffeID, fakeAudiences, time.Now().Add(time.Hour), ec256Key, "ec256Key")
	s.Require().NoError(err)
	s.Require().NotEmpty(token)

	spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, fakeAudiences[0:1])
	s.Require().NoError(err)
	s.Require().Equal(fakeSpiffeID, spiffeID)
	s.Require().NotEmpty(claims)
}

func (s *TokenSuite) TestSignWithNoExpiration() {
	_, err := s.signer.SignToken(fakeSpiffeID, fakeAudience, time.Time{}, ec256Key, "ec256Key")
	s.Require().EqualError(err, "expiration is required")
}

func (s *TokenSuite) TestSignInvalidSpiffeID() {
	// missing ID
	_, err := s.signer.SignToken("", fakeAudience, time.Now(), ec256Key, "ec256Key")
	s.RequireErrorContains(err, "is not a valid workload SPIFFE ID: SPIFFE ID is empty")

	// not a spiffe ID
	_, err = s.signer.SignToken("sparfe://example.org", fakeAudience, time.Now(), ec256Key, "ec256Key")
	s.RequireErrorContains(err, "is not a valid workload SPIFFE ID: invalid scheme")
}

func (s *TokenSuite) TestSignNoAudience() {
	_, err := s.signer.SignToken(fakeSpiffeID, nil, time.Now().Add(time.Hour), ec256Key, "ec256Key")
	s.Require().EqualError(err, "audience is required")
}

func (s *TokenSuite) TestSignEmptyAudience() {
	_, err := s.signer.SignToken(fakeSpiffeID, []string{""}, time.Now().Add(time.Hour), ec256Key, "ec256Key")
	s.Require().EqualError(err, "audience is required")
}

func (s *TokenSuite) TestValidateBadAlgorithm() {
	token := s.signToken(jose.HS256, []byte("BLAH"), jwt.Claims{})

	spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, fakeAudience[0:1])
	s.Require().EqualError(err, `unsupported token signature algorithm "HS256"`)
	s.Require().Empty(spiffeID)
	s.Require().Nil(claims)
}

func (s *TokenSuite) TestValidateMissingThumbprint() {
	token := s.signToken(jose.ES256, ec256Key, jwt.Claims{})

	spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, fakeAudience[0:1])
	s.Require().EqualError(err, "token header missing key id")
	s.Require().Empty(spiffeID)
	s.Require().Nil(claims)
}

func (s *TokenSuite) TestValidateExpiredToken() {
	token, err := s.signer.SignToken(fakeSpiffeID, fakeAudience, time.Now().Add(-time.Hour), ec256Key, "ec256Key")
	s.Require().NoError(err)
	s.Require().NotEmpty(token)

	spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, fakeAudience[0:1])
	s.Require().EqualError(err, "token has expired")
	s.Require().Empty(spiffeID)
	s.Require().Nil(claims)
}

func (s *TokenSuite) TestValidateNoSubject() {
	token := s.signToken(jose.ES256, jose.JSONWebKey{Key: ec256Key, KeyID: "ec256Key"}, jwt.Claims{
		Audience: []string{"audience"},
	})

	spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, []string{"FOO"})
	s.Require().EqualError(err, "token missing subject claim")
	s.Require().Empty(spiffeID)
	s.Require().Nil(claims)
}

func (s *TokenSuite) TestValidateSubjectNotForDomain() {
	token := s.signToken(jose.ES256, jose.JSONWebKey{Key: ec256Key, KeyID: "ec256Key"}, jwt.Claims{
		Subject:  "spiffe://other.org/foo",
		Audience: []string{"audience"},
	})

	spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, []string{"FOO"})
	s.Require().EqualError(err, `no keys found for trust domain "spiffe://other.org"`)
	s.Require().Empty(spiffeID)
	s.Require().Nil(claims)
}

func (s *TokenSuite) TestValidateNoAudience() {
	token := s.signToken(jose.ES256, jose.JSONWebKey{Key: ec256Key, KeyID: "ec256Key"}, jwt.Claims{
		Subject: fakeSpiffeID,
	})

	spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, []string{"FOO"})
	s.Require().EqualError(err, `expected audience in ["FOO"] (audience=[])`)
	s.Require().Empty(spiffeID)
	s.Require().Nil(claims)
}

func (s *TokenSuite) TestValidateUnexpectedAudience() {
	token, err := s.signer.SignToken(fakeSpiffeID, fakeAudience, time.Now().Add(time.Hour), ec256Key, "ec256Key")
	s.Require().NoError(err)
	s.Require().NotEmpty(token)

	spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, []string{"FOO"})
	s.Require().EqualError(err, `expected audience in ["FOO"] (audience=["AUDIENCE"])`)
	s.Require().Empty(spiffeID)
	s.Require().Nil(claims)
}

func (s *TokenSuite) TestValidateUnexpectedAudienceList() {
	token, err := s.signer.SignToken(fakeSpiffeID, fakeAudiences, time.Now().Add(time.Hour), ec256Key, "ec256Key")
	s.Require().NoError(err)
	s.Require().NotEmpty(token)

	spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, []string{"AUDIENCE3"})
	s.Require().EqualError(err, `expected audience in ["AUDIENCE3"] (audience=["AUDIENCE1" "AUDIENCE2"])`)
	s.Require().Empty(spiffeID)
	s.Require().Nil(claims)
}

func (s *TokenSuite) TestValidateKeyNotFound() {
	token, err := s.signer.SignToken(fakeSpiffeID, fakeAudience, time.Now().Add(time.Hour), ec256Key, "whatever")
	s.Require().NoError(err)
	s.Require().NotEmpty(token)

	spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, fakeAudience[0:1])
	s.Require().EqualError(err, `public key "whatever" not found in trust domain "spiffe://example.org"`)
	s.Require().Empty(spiffeID)
	s.Require().Nil(claims)
}

func (s *TokenSuite) signToken(alg jose.SignatureAlgorithm, key interface{}, claims jwt.Claims) string {
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: alg,
			Key:       key,
		}, nil)
	s.Require().NoError(err)

	token, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	s.Require().NoError(err)
	return token
}
