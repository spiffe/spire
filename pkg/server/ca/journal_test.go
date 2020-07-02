package ca

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/suite"
)

var (
	testChain = []*x509.Certificate{
		{Raw: []byte("A")},
		{Raw: []byte("B")},
		{Raw: []byte("C")},
	}

	jsonAnoB = `{
	"cas": {
		"x509-CA-A": "MIIBzDCCAVGgAwIBAgIBADAKBggqhkjOPQQDAzAeMQswCQYDVQQGEwJVUzEPMA0GA1UEChMGU1BJRkZFMB4XDTE5MDQwOTIwMDI1MloXDTE5MDQwOTIwMDYwMlowHjELMAkGA1UEBhMCVVMxDzANBgNVBAoTBlNQSUZGRTB2MBAGByqGSM49AgEGBSuBBAAiA2IABK4EOWwzY2prE+4Jnj0u4QmDUiCWDm6mtnXITSDcxprGk26gtzH70L5sUV9nqaAdPBtLhrdD8rbK+z4eCJnTk1tCOF54DaJc4qCx3uUtpDbgW/8BClkWGBWcRHWQsK8CJKNjMGEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFNdeIMP8EtI03I/D26N2xOXSCq3wMB8GA1UdEQQYMBaGFHNwaWZmZTovL2V4YW1wbGUub3JnMAoGCCqGSM49BAMDA2kAMGYCMQDXSYCiWeyx9i+irU0ke/bB2RKy65qXuNaW3VzE8MVmDYnMlGLeuFSG4eW3f64nczgCMQDSGHzzKtTyfL90DFDkDxSf738HIqyycr/LnbkvQJn/CG0sJbbQrttL4dzCFHlmQ2k="
	},
	"public_keys": {
		"JWT-Signer-A": "ClswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARFWYjoAMoGTBoxXAbxzLKap2KcKAUzvBE23h3HRu3H7A0iyTT5KRRenszcv/oDTtzVvGJ9n2jrzTcvEeqlvQrUEiBSZFBrOTFYZ2U0R1I1eTU5R25IYjU3T3VXeEN3dHZOUBiq9rPlBQ=="
	}
}
`

	jsonBnoA = `{
	"cas": {
		"x509-CA-B": "MIIBzDCCAVGgAwIBAgIBADAKBggqhkjOPQQDAzAeMQswCQYDVQQGEwJVUzEPMA0GA1UEChMGU1BJRkZFMB4XDTE5MDQwOTIwMDI1MloXDTE5MDQwOTIwMDYwMlowHjELMAkGA1UEBhMCVVMxDzANBgNVBAoTBlNQSUZGRTB2MBAGByqGSM49AgEGBSuBBAAiA2IABK4EOWwzY2prE+4Jnj0u4QmDUiCWDm6mtnXITSDcxprGk26gtzH70L5sUV9nqaAdPBtLhrdD8rbK+z4eCJnTk1tCOF54DaJc4qCx3uUtpDbgW/8BClkWGBWcRHWQsK8CJKNjMGEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFNdeIMP8EtI03I/D26N2xOXSCq3wMB8GA1UdEQQYMBaGFHNwaWZmZTovL2V4YW1wbGUub3JnMAoGCCqGSM49BAMDA2kAMGYCMQDXSYCiWeyx9i+irU0ke/bB2RKy65qXuNaW3VzE8MVmDYnMlGLeuFSG4eW3f64nczgCMQDSGHzzKtTyfL90DFDkDxSf738HIqyycr/LnbkvQJn/CG0sJbbQrttL4dzCFHlmQ2k="
	},
	"public_keys": {
		"JWT-Signer-B": "ClswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARFWYjoAMoGTBoxXAbxzLKap2KcKAUzvBE23h3HRu3H7A0iyTT5KRRenszcv/oDTtzVvGJ9n2jrzTcvEeqlvQrUEiBSZFBrOTFYZ2U0R1I1eTU5R25IYjU3T3VXeEN3dHZOUBiq9rPlBQ=="
	}
}
`

	jsonAthenB = `{
	"certs": null,
	"cas": {
		"x509-CA-A": "MIIBzDCCAVGgAwIBAgIBADAKBggqhkjOPQQDAzAeMQswCQYDVQQGEwJVUzEPMA0GA1UEChMGU1BJRkZFMB4XDTE5MDQwOTIwMDI1MloXDTE5MDQwOTIwMDYwMlowHjELMAkGA1UEBhMCVVMxDzANBgNVBAoTBlNQSUZGRTB2MBAGByqGSM49AgEGBSuBBAAiA2IABK4EOWwzY2prE+4Jnj0u4QmDUiCWDm6mtnXITSDcxprGk26gtzH70L5sUV9nqaAdPBtLhrdD8rbK+z4eCJnTk1tCOF54DaJc4qCx3uUtpDbgW/8BClkWGBWcRHWQsK8CJKNjMGEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFNdeIMP8EtI03I/D26N2xOXSCq3wMB8GA1UdEQQYMBaGFHNwaWZmZTovL2V4YW1wbGUub3JnMAoGCCqGSM49BAMDA2kAMGYCMQDXSYCiWeyx9i+irU0ke/bB2RKy65qXuNaW3VzE8MVmDYnMlGLeuFSG4eW3f64nczgCMQDSGHzzKtTyfL90DFDkDxSf738HIqyycr/LnbkvQJn/CG0sJbbQrttL4dzCFHlmQ2k=",
		"x509-CA-B": "MIIByzCCAVGgAwIBAgIBADAKBggqhkjOPQQDAzAeMQswCQYDVQQGEwJVUzEPMA0GA1UEChMGU1BJRkZFMB4XDTE5MDQwOTIwMDQ1MloXDTE5MDQwOTIwMDgwMlowHjELMAkGA1UEBhMCVVMxDzANBgNVBAoTBlNQSUZGRTB2MBAGByqGSM49AgEGBSuBBAAiA2IABIn5wgdDz14/rlZbEE0DSi6q4d7b7BXLddOKvR3oNbbf3QNZZnIwLvqyn+fmqinrDKCPS4xD8fJjrSxMN3DXCiUPp1ihZfV20Kc7Pngs1N6W+ig7I8TPErXsZCx9YQB1WKNjMGEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFJQE4qYo/ihjOczg4OEy+rftQ6luMB8GA1UdEQQYMBaGFHNwaWZmZTovL2V4YW1wbGUub3JnMAoGCCqGSM49BAMDA2gAMGUCMQCmcFZfEYJrrqe8TCYoBiX/KQm3IAOHXd0WcuRjdzUnfzXBh9eXgcPq+/Hg3WYzzxECMCn4IPw6LmqvUczFtJwOr9ZZOKoXJw14vw+M25kXTf2ip9O7tCn5S8SQqEgdai1ixg=="
	},
	"public_keys": {
		"JWT-Signer-A": "ClswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARFWYjoAMoGTBoxXAbxzLKap2KcKAUzvBE23h3HRu3H7A0iyTT5KRRenszcv/oDTtzVvGJ9n2jrzTcvEeqlvQrUEiBSZFBrOTFYZ2U0R1I1eTU5R25IYjU3T3VXeEN3dHZOUBiq9rPlBQ==",
		"JWT-Signer-B": "ClswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATK46lsHWiVYxqwqSlMCOJD+L5ZHPIHCkoWSMNVMASR8J4nw47PLLMm0Vjttf1VvZ1IgANXotvgNTC2jsSN9xG5EiBBN2RxMGVrdmZFVjV1WURjc3Rhb0NmeVU1SnQ3N2RsWhii97PlBQ=="
	}
}
`

	jsonBthenA = `{
	"certs": null,
	"cas": {
		"x509-CA-A": "MIIBzDCCAVGgAwIBAgIBADAKBggqhkjOPQQDAzAeMQswCQYDVQQGEwJVUzEPMA0GA1UEChMGU1BJRkZFMB4XDTE5MDQwOTIwMDI1MloXDTE5MDQwOTIwMDYwMlowHjELMAkGA1UEBhMCVVMxDzANBgNVBAoTBlNQSUZGRTB2MBAGByqGSM49AgEGBSuBBAAiA2IABK4EOWwzY2prE+4Jnj0u4QmDUiCWDm6mtnXITSDcxprGk26gtzH70L5sUV9nqaAdPBtLhrdD8rbK+z4eCJnTk1tCOF54DaJc4qCx3uUtpDbgW/8BClkWGBWcRHWQsK8CJKNjMGEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFNdeIMP8EtI03I/D26N2xOXSCq3wMB8GA1UdEQQYMBaGFHNwaWZmZTovL2V4YW1wbGUub3JnMAoGCCqGSM49BAMDA2kAMGYCMQDXSYCiWeyx9i+irU0ke/bB2RKy65qXuNaW3VzE8MVmDYnMlGLeuFSG4eW3f64nczgCMQDSGHzzKtTyfL90DFDkDxSf738HIqyycr/LnbkvQJn/CG0sJbbQrttL4dzCFHlmQ2k=",
		"x509-CA-B": "MIIByjCCAVGgAwIBAgIBADAKBggqhkjOPQQDAzAeMQswCQYDVQQGEwJVUzEPMA0GA1UEChMGU1BJRkZFMB4XDTE5MDQwOTIwMDA1MloXDTE5MDQwOTIwMDQwMlowHjELMAkGA1UEBhMCVVMxDzANBgNVBAoTBlNQSUZGRTB2MBAGByqGSM49AgEGBSuBBAAiA2IABM5fBRPvXbqxTB+yQcBoVg6CPIrsLoCyU41DZtYDit14b3rUnqXA06K8B4Qjn4azW3uRZsKDtZA2PMWjC/hfDP774H3CknsMEi6vkqDaB+lVGO+ocv3KRm4yy4dSd/f46qNjMGEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFKyuzfdhC8MFX0LzuHDKZKcJkXBDMB8GA1UdEQQYMBaGFHNwaWZmZTovL2V4YW1wbGUub3JnMAoGCCqGSM49BAMDA2cAMGQCMGjx1KaaGVKdK/IwbRE1YHK5QlVcYQHysw2YA5A0Nj6camSm02vsR/9mWC3ibodP7QIwRoRlOAguhRtZGaOWjyaPXLqXDv90e//P+aGlzPRB6KpQtRoW/ZjXq0P5/l6++gkl"
	},
	"public_keys": {
		"JWT-Signer-A": "ClswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARFWYjoAMoGTBoxXAbxzLKap2KcKAUzvBE23h3HRu3H7A0iyTT5KRRenszcv/oDTtzVvGJ9n2jrzTcvEeqlvQrUEiBSZFBrOTFYZ2U0R1I1eTU5R25IYjU3T3VXeEN3dHZOUBiq9rPlBQ==",
		"JWT-Signer-B": "ClswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ1UlhEDpg/M0EIilDPbSRlWmDleeuG4CfEBsx8b0rqvn5Gpa3nZH2rkib01eM1bSK8rREgef4NRQUtK9wChEQiEiBxc2I2YnBHd0N3UzZGWnFFczByWlBtQmYzMHVXaEE0ehiy9bPlBQ=="
	}
}
`

	jsonX509CASelfSigned = `{
	"cas": {
		"x509-CA-A": "MIIBzDCCAVGgAwIBAgIBADAKBggqhkjOPQQDAzAeMQswCQYDVQQGEwJVUzEPMA0GA1UEChMGU1BJRkZFMB4XDTE5MDQwOTIwMDI1MloXDTE5MDQwOTIwMDYwMlowHjELMAkGA1UEBhMCVVMxDzANBgNVBAoTBlNQSUZGRTB2MBAGByqGSM49AgEGBSuBBAAiA2IABK4EOWwzY2prE+4Jnj0u4QmDUiCWDm6mtnXITSDcxprGk26gtzH70L5sUV9nqaAdPBtLhrdD8rbK+z4eCJnTk1tCOF54DaJc4qCx3uUtpDbgW/8BClkWGBWcRHWQsK8CJKNjMGEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFNdeIMP8EtI03I/D26N2xOXSCq3wMB8GA1UdEQQYMBaGFHNwaWZmZTovL2V4YW1wbGUub3JnMAoGCCqGSM49BAMDA2kAMGYCMQDXSYCiWeyx9i+irU0ke/bB2RKy65qXuNaW3VzE8MVmDYnMlGLeuFSG4eW3f64nczgCMQDSGHzzKtTyfL90DFDkDxSf738HIqyycr/LnbkvQJn/CG0sJbbQrttL4dzCFHlmQ2k="
	},
	"public_keys": {
		"JWT-Signer-A": "ClswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARFWYjoAMoGTBoxXAbxzLKap2KcKAUzvBE23h3HRu3H7A0iyTT5KRRenszcv/oDTtzVvGJ9n2jrzTcvEeqlvQrUEiBSZFBrOTFYZ2U0R1I1eTU5R25IYjU3T3VXeEN3dHZOUBiq9rPlBQ=="
	}
}
`

	jsonX509CAUpstreamRootWithBundle = `{
	"cas": {
		"x509-CA-A": "MIIBbTCCARSgAwIBAgIBATAKBggqhkjOPQQDAjAZMRcwFQYDVQQDEw5GQUtFVVBTVFJFQU1DQTAeFw0xOTA0MTUxNzQyMjlaFw0xOTA0MTUxODQyMzlaMAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATA/QudaCHS+SIdorglqmSANMf7qZsuzFoQQSb86LNz+t2Jy/3Ydrwln2AGsii8NKRr9xAVcWR6wR/lVmen81SHo2YwZDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU3kf0/nNHcHpTb1lbGhzlcT/rt24wIgYDVR0RAQH/BBgwFoYUc3BpZmZlOi8vZG9tYWluLnRlc3QwCgYIKoZIzj0EAwIDRwAwRAIgMMPAokgpzURcMCPSc/Zn+CXRxwKapiCxSc0A0uQoWH4CICNFEWlgWCZ/0pSD4odB80U+DtdfgfvyODr3lkni2m+VMIIBNTCB3KADAgECAgEBMAoGCCqGSM49BAMCMBkxFzAVBgNVBAMTDkZBS0VVUFNUUkVBTUNBMCAYDzAwMDEwMTAxMDAwMDAwWhcNMTkwNDE1MTg0MjM5WjAZMRcwFQYDVQQDEw5GQUtFVVBTVFJFQU1DQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMN7/Z3rP4/T3kjd0iShwqvhvfMDL7WpAO6hepryLdg4+Tl8uJvg5HOoP00kVysqMj4su2KlB73K795jUrTKEFqjEzARMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgJ5++zGfBJEgN5ymvwRq8VzT3PUuW2NhCpq8Drx/ZeIECIQCU+64Kln9YiryOZUYl/XhbajhN4mwGGOU72DBsd2kqYA=="
	},
	"public_keys": {
		"JWT-Signer-A": "ClswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARFWYjoAMoGTBoxXAbxzLKap2KcKAUzvBE23h3HRu3H7A0iyTT5KRRenszcv/oDTtzVvGJ9n2jrzTcvEeqlvQrUEiBSZFBrOTFYZ2U0R1I1eTU5R25IYjU3T3VXeEN3dHZOUBiq9rPlBQ=="
	}
}
`

	jsonX509CAUpstreamIntWithBundle = `{
	"cas": {
		"x509-CA-A": "MIIBcjCCARigAwIBAgIBATAKBggqhkjOPQQDAjAdMRswGQYDVQQDExJGQUtFVVBTVFJFQU1DQS1JTlQwHhcNMTkwNDE1MTc0MDU4WhcNMTkwNDE1MTg0MTA4WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwP0LnWgh0vkiHaK4JapkgDTH+6mbLsxaEEEm/Oizc/rdicv92Ha8JZ9gBrIovDSka/cQFXFkesEf5VZnp/NUh6NmMGQwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFN5H9P5zR3B6U29ZWxoc5XE/67duMCIGA1UdEQEB/wQYMBaGFHNwaWZmZTovL2RvbWFpbi50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIQDWJcipwPNWlJfGfg5O9zhDyWsSJ7d67PdQi5olzKiVQwIgbO3lIZqjdwNXzMzo0rfXZe9czEFDvUSHdXI87FTs03gwggE5MIHgoAMCAQICAQEwCgYIKoZIzj0EAwIwGTEXMBUGA1UEAxMORkFLRVVQU1RSRUFNQ0EwIBgPMDAwMTAxMDEwMDAwMDBaFw0xOTA0MTUxODQxMDhaMB0xGzAZBgNVBAMTEkZBS0VVUFNUUkVBTUNBLUlOVDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMD9C51oIdL5Ih2iuCWqZIA0x/upmy7MWhBBJvzos3P63YnL/dh2vCWfYAayKLw0pGv3EBVxZHrBH+VWZ6fzVIejEzARMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgUrVwexOk57QAc0XAaakZG46h/Ndhzc1nMwwL4hQfkaACIQDFWh88FRn4dqFwm5veSglnQvbUXUkExc3jFPTAqSYZRDCCATYwgdygAwIBAgIBATAKBggqhkjOPQQDAjAZMRcwFQYDVQQDEw5GQUtFVVBTVFJFQU1DQTAgGA8wMDAxMDEwMTAwMDAwMFoXDTE5MDQxNTE4NDEwOFowGTEXMBUGA1UEAxMORkFLRVVQU1RSRUFNQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATDe/2d6z+P095I3dIkocKr4b3zAy+1qQDuoXqa8i3YOPk5fLib4ORzqD9NJFcrKjI+LLtipQe9yu/eY1K0yhBaoxMwETAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQD/o90qq6KjmgZbBxxQPUN7ltfqLzbaNcBnrufkExpD0AIhANf2G9o7o7kTYDSesHoOjji19cUNJPpxnQwXqvbqXMqS"
	},
	"public_keys": {
		"JWT-Signer-A": "ClswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARFWYjoAMoGTBoxXAbxzLKap2KcKAUzvBE23h3HRu3H7A0iyTT5KRRenszcv/oDTtzVvGJ9n2jrzTcvEeqlvQrUEiBSZFBrOTFYZ2U0R1I1eTU5R25IYjU3T3VXeEN3dHZOUBiq9rPlBQ=="
	}
}
`
)

func TestJournal(t *testing.T) {
	suite.Run(t, new(JournalSuite))
}

type JournalSuite struct {
	suite.Suite
	dir string
}

func (s *JournalSuite) SetupTest() {
	dir, err := ioutil.TempDir("", "spire-server-ca-journal")
	s.Require().NoError(err)
	s.dir = dir
}

func (s *JournalSuite) TearDownTest() {
	os.RemoveAll(s.dir)
}

func (s *JournalSuite) TestNew() {
	journal, err := LoadJournal(s.journalPath())
	s.NoError(err)
	if s.NotNil(journal) {
		s.Empty(journal.Entries())
	}
}

func (s *JournalSuite) TestPersistence() {
	now := s.now()

	journal := s.loadJournal()

	err := journal.AppendX509CA("A", now, &X509CA{
		Signer:        testSigner,
		Certificate:   testChain[0],
		UpstreamChain: testChain,
	})
	s.Require().NoError(err)

	err = journal.AppendJWTKey("B", now, &JWTKey{
		Signer:   testSigner,
		Kid:      "KID",
		NotAfter: now.Add(time.Hour),
	})
	s.Require().NoError(err)

	s.requireProtoEqual(journal.Entries(), s.loadJournal().Entries())
}

func (s *JournalSuite) TestX509CAOverflow() {
	now := s.now()

	journal := s.loadJournal()

	for i := 0; i < (journalCap + 1); i++ {
		now = now.Add(time.Minute)
		err := journal.AppendX509CA("A", now, &X509CA{
			Signer:      testSigner,
			Certificate: testChain[0],
		})
		s.Require().NoError(err)
	}

	entries := journal.Entries()
	s.Require().Len(entries.X509CAs, journalCap, "X509CA entries exceeds cap")
	lastEntry := entries.X509CAs[len(entries.X509CAs)-1]
	s.Require().Equal(now, time.Unix(lastEntry.IssuedAt, 0).UTC())
}

func (s *JournalSuite) TestJWTKeyOverflow() {
	now := s.now()

	journal := s.loadJournal()

	for i := 0; i < (journalCap + 1); i++ {
		now = now.Add(time.Minute)
		err := journal.AppendJWTKey("B", now, &JWTKey{
			Signer:   testSigner,
			Kid:      "KID",
			NotAfter: now.Add(time.Hour),
		})
		s.Require().NoError(err)
	}

	entries := journal.Entries()
	s.Require().Len(entries.JwtKeys, journalCap, "JWT key entries exceeds cap")
	lastEntry := entries.JwtKeys[len(entries.JwtKeys)-1]
	s.Require().Equal(now, time.Unix(lastEntry.IssuedAt, 0).UTC())
}

func (s *JournalSuite) TestBadPEM() {
	s.writeString(s.journalPath(), "NOT PEM")
	_, err := LoadJournal(s.journalPath())
	s.EqualError(err, "invalid PEM block")
}

func (s *JournalSuite) TestUnexpectedPEMType() {
	s.writeBytes(s.journalPath(), pem.EncodeToMemory(&pem.Block{
		Type:  "WHATEVER",
		Bytes: []byte("FOO"),
	}))
	_, err := LoadJournal(s.journalPath())
	s.EqualError(err, `invalid PEM block type "WHATEVER"`)
}

func (s *JournalSuite) TestBadProto() {
	s.writeBytes(s.journalPath(), pem.EncodeToMemory(&pem.Block{
		Type:  journalPEMType,
		Bytes: []byte("FOO"),
	}))
	_, err := LoadJournal(s.journalPath())
	s.Require().Error(err)
	s.Contains(err.Error(), `unable to unmarshal entries: `)
}

func (s *JournalSuite) TestMigrationOrdering() {
	// migrate data with only an A pair
	entries := s.migrateThenLoad(jsonAnoB)
	s.Require().Len(entries.X509CAs, 1)
	s.Require().Len(entries.JwtKeys, 1)
	s.Equal("A", entries.X509CAs[0].SlotId)
	s.Equal("A", entries.JwtKeys[0].SlotId)

	// migrate data with only a B pair
	entries = s.migrateThenLoad(jsonBnoA)
	s.Require().Len(entries.X509CAs, 1)
	s.Require().Len(entries.JwtKeys, 1)
	s.Equal("B", entries.X509CAs[0].SlotId)
	s.Equal("B", entries.JwtKeys[0].SlotId)

	// migrate data with an A pair followed by a B pair
	entries = s.migrateThenLoad(jsonAthenB)
	s.Require().Len(entries.X509CAs, 2)
	s.Require().Len(entries.JwtKeys, 2)
	s.Equal("A", entries.X509CAs[0].SlotId)
	s.Equal("A", entries.JwtKeys[0].SlotId)
	s.Equal("B", entries.X509CAs[1].SlotId)
	s.Equal("B", entries.JwtKeys[1].SlotId)

	// migrate data with a B pair followed by an A pair
	entries = s.migrateThenLoad(jsonBthenA)
	s.Require().Len(entries.X509CAs, 2)
	s.Require().Len(entries.JwtKeys, 2)
	s.Equal("B", entries.X509CAs[0].SlotId)
	s.Equal("B", entries.JwtKeys[0].SlotId)
	s.Equal("A", entries.X509CAs[1].SlotId)
	s.Equal("A", entries.JwtKeys[1].SlotId)
}

func (s *JournalSuite) TestX509CAChainMigration() {
	// self signed
	entries := s.migrateThenLoad(jsonX509CASelfSigned)
	s.Require().Len(entries.X509CAs, 1)
	s.NotNil(entries.X509CAs[0].Certificate)
	s.Empty(entries.X509CAs[0].UpstreamChain)

	// signed by upstream root and upstream bundle is used
	entries = s.migrateThenLoad(jsonX509CAUpstreamRootWithBundle)
	s.Require().Len(entries.X509CAs, 1)
	s.NotNil(entries.X509CAs[0].Certificate)
	s.Len(entries.X509CAs[0].UpstreamChain, 1)

	// signed by upstream intermediate and upstream bundle is used
	entries = s.migrateThenLoad(jsonX509CAUpstreamIntWithBundle)
	s.Require().Len(entries.X509CAs, 1)
	s.NotNil(entries.X509CAs[0].Certificate)
	s.Len(entries.X509CAs[0].UpstreamChain, 2)
}

func (s *JournalSuite) loadJournal() *Journal {
	journal, err := LoadJournal(s.journalPath())
	s.Require().NoError(err)
	return journal
}

func (s *JournalSuite) migrateThenLoad(jsonData string) *JournalEntries {
	s.writeString(s.pathTo("certs.json"), jsonData)
	ok, err := migrateJSONFile(s.pathTo("certs.json"), s.journalPath())
	s.Require().NoError(err)
	s.Require().True(ok, "migration did not occur")
	_, err = os.Stat(s.pathTo("certs.json"))
	s.Require().True(os.IsNotExist(err), "JSON file was not removed after migration")
	return s.loadJournal().Entries()
}

func (s *JournalSuite) journalPath() string {
	return s.pathTo("journal.pem")
}

func (s *JournalSuite) pathTo(relativePath string) string {
	return filepath.Join(s.dir, relativePath)
}

func (s *JournalSuite) writeString(path, data string) {
	s.writeBytes(path, []byte(data))
}

func (s *JournalSuite) writeBytes(path string, data []byte) {
	s.Require().NoError(ioutil.WriteFile(path, data, 0644))
}

func (s *JournalSuite) now() time.Time {
	// return truncated UTC time for cleaner failure messages
	return time.Now().UTC().Truncate(time.Second)
}

func (s *JournalSuite) requireProtoEqual(expected, actual proto.Message) {
	if !proto.Equal(expected, actual) {
		s.Require().Equal(expected, actual)
	}
}
