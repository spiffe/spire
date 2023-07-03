package manager

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/proto/private/server/journal"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/proto"
)

var (
	testSigner, _ = pemutil.ParseSigner([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgt/OIyb8Ossz/5bNk
XtnzFe1T2d0D9quX9Loi1O55b8yhRANCAATDe/2d6z+P095I3dIkocKr4b3zAy+1
qQDuoXqa8i3YOPk5fLib4ORzqD9NJFcrKjI+LLtipQe9yu/eY1K0yhBa
-----END PRIVATE KEY-----
`))

	testChain = []*x509.Certificate{
		{Raw: []byte("A")},
		{Raw: []byte("B")},
		{Raw: []byte("C")},
	}
)

func TestJournal(t *testing.T) {
	suite.Run(t, new(JournalSuite))
}

type JournalSuite struct {
	spiretest.Suite
	dir string
}

func (s *JournalSuite) SetupTest() {
	s.dir = s.TempDir()
}

func (s *JournalSuite) TestNew() {
	journal, err := LoadJournal(s.journalPath())
	s.NoError(err)
	if s.NotNil(journal) {
		// Verify entries is empty
		s.AssertProtoEqual(&JournalEntries{}, journal.Entries())
	}
}

func (s *JournalSuite) TestPersistence() {
	now := s.now()

	journal := s.loadJournal()

	err := journal.AppendX509CA("A", now, &ca.X509CA{
		Signer:        testSigner,
		Certificate:   testChain[0],
		UpstreamChain: testChain,
	})
	s.Require().NoError(err)

	err = journal.AppendJWTKey("B", now, &ca.JWTKey{
		Signer:   testSigner,
		Kid:      "KID",
		NotAfter: now.Add(time.Hour),
	})
	s.Require().NoError(err)

	s.requireProtoEqual(journal.Entries(), s.loadJournal().Entries())
}

func (s *JournalSuite) TestAppendSetPreparedStatus() {
	t := s.T()
	now := s.now()

	testJournal := s.loadJournal()

	err := testJournal.AppendX509CA("A", now, &ca.X509CA{
		Signer:        testSigner,
		Certificate:   testChain[0],
		UpstreamChain: testChain,
	})
	require.NoError(t, err)

	require.Len(t, testJournal.entries.X509CAs, 1)
	lastX509CA := testJournal.entries.X509CAs[0]
	require.Equal(t, "A", lastX509CA.SlotId)
	require.Equal(t, journal.Status_PREPARED, lastX509CA.Status)

	err = testJournal.AppendJWTKey("B", now, &ca.JWTKey{
		Signer:   testSigner,
		Kid:      "KID",
		NotAfter: now.Add(time.Hour),
	})
	require.NoError(t, err)

	require.Len(t, testJournal.entries.JwtKeys, 1)
	lastJWTKey := testJournal.entries.JwtKeys[0]
	require.Equal(t, "B", lastJWTKey.SlotId)
	require.Equal(t, journal.Status_PREPARED, lastJWTKey.Status)
}

func (s *JournalSuite) TestX509CAOverflow() {
	now := s.now()

	journal := s.loadJournal()

	for i := 0; i < (journalCap + 1); i++ {
		now = now.Add(time.Minute)
		err := journal.AppendX509CA("A", now, &ca.X509CA{
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

func (s *JournalSuite) TestUpdateX509CAStatus() {
	t := s.T()
	firstIssuedAt := s.now()
	secondIssuedAt := firstIssuedAt.Add(time.Minute)
	thirdIssuedAt := secondIssuedAt.Add(time.Minute)

	testJournal := s.loadJournal()

	err := testJournal.AppendX509CA("A", firstIssuedAt, &ca.X509CA{
		Signer:      testSigner,
		Certificate: testChain[0],
	})
	require.NoError(t, err)

	err = testJournal.AppendX509CA("B", secondIssuedAt, &ca.X509CA{
		Signer:      testSigner,
		Certificate: testChain[0],
	})
	require.NoError(t, err)

	err = testJournal.AppendX509CA("C", thirdIssuedAt, &ca.X509CA{
		Signer:      testSigner,
		Certificate: testChain[0],
	})
	require.NoError(t, err)

	cas := testJournal.entries.X509CAs
	require.Len(t, cas, 3)
	for _, ca := range cas {
		require.Equal(t, journal.Status_PREPARED, ca.Status)
	}

	err = testJournal.UpdateX509CAStatus(secondIssuedAt, journal.Status_ACTIVE)
	require.NoError(t, err)

	for _, ca := range testJournal.Entries().X509CAs {
		expectedStatus := journal.Status_PREPARED
		if ca.SlotId == "B" {
			expectedStatus = journal.Status_ACTIVE
		}

		require.Equal(t, expectedStatus, ca.Status)
	}

	unusedTime := s.now().Add(time.Hour)
	err = testJournal.UpdateX509CAStatus(unusedTime, journal.Status_OLD)
	require.ErrorContains(t, err, "no journal entry found issued at:")
}

func (s *JournalSuite) TestUpdateJWTKeyStatus() {
	t := s.T()
	firstIssuedAt := s.now()
	secondIssuedAt := firstIssuedAt.Add(time.Minute)
	thirdIssuedAt := secondIssuedAt.Add(time.Minute)

	testJournal := s.loadJournal()

	err := testJournal.AppendJWTKey("A", firstIssuedAt, &ca.JWTKey{
		Signer: testSigner,
		Kid:    "kid1",
	})
	require.NoError(t, err)

	err = testJournal.AppendJWTKey("B", secondIssuedAt, &ca.JWTKey{
		Signer: testSigner,
		Kid:    "kid2",
	})
	require.NoError(t, err)

	err = testJournal.AppendJWTKey("C", thirdIssuedAt, &ca.JWTKey{
		Signer: testSigner,
		Kid:    "kid3",
	})
	require.NoError(t, err)

	keys := testJournal.Entries().JwtKeys
	require.Len(t, keys, 3)
	for _, key := range keys {
		require.Equal(t, journal.Status_PREPARED, key.Status)
	}

	err = testJournal.UpdateJWTKeyStatus(secondIssuedAt, journal.Status_ACTIVE)
	require.NoError(t, err)

	for _, key := range testJournal.Entries().JwtKeys {
		expectedStatus := journal.Status_PREPARED
		if key.SlotId == "B" {
			expectedStatus = journal.Status_ACTIVE
		}

		require.Equal(t, expectedStatus, key.Status)
	}

	unusedTime := s.now().Add(time.Hour)
	err = testJournal.UpdateJWTKeyStatus(unusedTime, journal.Status_OLD)
	require.ErrorContains(t, err, "no journal entry found issued at:")
}

func (s *JournalSuite) TestJWTKeyOverflow() {
	now := s.now()

	journal := s.loadJournal()

	for i := 0; i < (journalCap + 1); i++ {
		now = now.Add(time.Minute)
		err := journal.AppendJWTKey("B", now, &ca.JWTKey{
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

func (s *JournalSuite) loadJournal() *Journal {
	journal, err := LoadJournal(s.journalPath())
	s.Require().NoError(err)
	return journal
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
	s.Require().NoError(os.WriteFile(path, data, 0600))
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
