package cli

import (
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
)

func TestParseTrustDomain(t *testing.T) {
	testCases := []struct {
		msg                string
		domain             string
		expectedDomain     string
		expectedLogEntries []spiretest.LogEntry
	}{
		{
			msg:            "too_long_warn",
			domain:         strings.Repeat("a", 256),
			expectedDomain: strings.Repeat("a", 256),
			expectedLogEntries: []spiretest.LogEntry{
				{
					Data:  map[string]interface{}{"trust_domain": strings.Repeat("a", 256)},
					Level: logrus.WarnLevel,
					Message: "Configured trust domain name should be less than 255 characters to be " +
						"SPIFFE compliant; a longer trust domain name may impact interoperability",
				},
			},
		},
		{
			msg:            "not_too_long",
			domain:         "spiffe://" + strings.Repeat("a", 255),
			expectedDomain: strings.Repeat("a", 255),
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.msg, func(t *testing.T) {
			logger, hook := logtest.NewNullLogger()
			td, err := ParseTrustDomain(testCase.domain, logger)
			assert.NoError(t, err)
			assert.Equal(t, testCase.expectedDomain, td.Name())
			spiretest.AssertLogs(t, hook.AllEntries(), testCase.expectedLogEntries)
		})
	}
}
