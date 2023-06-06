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
	"github.com/spiffe/spire/test/spiretest"
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
