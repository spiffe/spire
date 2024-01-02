package manager

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/credtemplate"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/proto/private/server/journal"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/fakes/fakeserverkeymanager"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	ctx = context.Background()

	testChain = []*x509.Certificate{
		{Raw: []byte("A")},
		{Raw: []byte("B")},
		{Raw: []byte("C")},
	}

	km        keymanager.KeyManager
	kmKeys    = map[string]keymanager.Key{}
	rootCerts = map[string]*x509.Certificate{}
)

func setupJournalTest(t *testing.T) *journalTest {
	log, _ := test.NewNullLogger()

	clk := clock.New()
	credBuilder, err := credtemplate.NewBuilder(credtemplate.Config{
		TrustDomain:   testTrustDomain,
		X509CASubject: pkix.Name{CommonName: "SPIRE"},
		Clock:         clk,
		X509CATTL:     testCATTL,
	})
	require.NoError(t, err)

	ds := fakedatastore.New(t)
	cat := fakeservercatalog.New()
	cat.SetDataStore(ds)

	if km == nil {
		km := fakeserverkeymanager.New(t)
		cat.SetKeyManager(km)

		kmKeys["X509-CA-A"], rootCerts["X509-Root-A"], err = createSelfSigned(ctx, credBuilder, km, "X509-CA-A")
		require.NoError(t, err)

		kmKeys["X509-CA-B"], rootCerts["X509-Root-B"], err = createSelfSigned(ctx, credBuilder, km, "x509-CA-B")
		require.NoError(t, err)

		kmKeys["X509-CA-C"], rootCerts["X509-Root-C"], err = createSelfSigned(ctx, credBuilder, km, "x509-CA-C")
		require.NoError(t, err)

		kmKeys["JWT-Signer-A"], err = km.GenerateKey(ctx, "JWT-Signer-A", keymanager.ECP256)
		require.NoError(t, err)

		kmKeys["JWT-Signer-B"], err = km.GenerateKey(ctx, "JWT-Signer-B", keymanager.ECP256)
		require.NoError(t, err)

		kmKeys["JWT-Signer-C"], err = km.GenerateKey(ctx, "JWT-Signer-C", keymanager.ECP256)
		require.NoError(t, err)
	}

	return &journalTest{
		ds: ds,
		jc: &journalConfig{
			cat:      cat,
			log:      log,
			filePath: filepath.Join(t.TempDir(), "journal.pem"),
		},
	}
}

func TestNew(t *testing.T) {
	test := setupJournalTest(t)
	j, err := LoadJournal(ctx, test.jc)
	require.NoError(t, err)
	if assert.NotNil(t, j) {
		// Verify entries is empty
		spiretest.RequireProtoEqual(t, &journal.Entries{}, j.getEntries())
	}
	caJournals, err := test.ds.ListCAJournalsForTesting(ctx)
	require.NoError(t, err)
	require.Empty(t, caJournals)
}

func TestJournalPersistence(t *testing.T) {
	test := setupJournalTest(t)
	now := test.now()

	j := test.loadJournal(t)

	err := j.AppendX509CA(ctx, "A", now, &ca.X509CA{
		Signer:        kmKeys["X509-CA-A"],
		Certificate:   rootCerts["X509-Root-A"],
		UpstreamChain: testChain,
	})
	require.NoError(t, err)

	err = j.AppendJWTKey(ctx, "B", now, &ca.JWTKey{
		Signer:   kmKeys["JWT-Signer-B"],
		Kid:      "kid1",
		NotAfter: now.Add(time.Hour),
	})
	require.NoError(t, err)

	require.NoError(t, j.UpdateX509CAStatus(ctx, now, journal.Status_ACTIVE))

	// Check that the CA journal was properly stored in the datastore.
	journalDS := test.loadJournalFromDS(t)
	require.NotNil(t, journalDS)
	spiretest.RequireProtoEqual(t, j.getEntries(), journalDS.getEntries())

	// TODO: the following checks assume that the CA journal is stored both in
	// datastore and on disk. Revisit this in v1.10.
	journalDisk := test.loadJournalFromDisk(t)
	require.NotNil(t, journalDisk)
	spiretest.RequireProtoEqual(t, j.getEntries(), journalDisk.getEntries())

	// Test for the case when SPIRE starts with a CA journal on disk and does
	// not yet have a CA journal stored in the datastore. Reset the datastore so
	// we only have the CA journal on disk.
	test.ds = fakedatastore.New(t)
	test.jc.cat.(*fakeservercatalog.Catalog).SetDataStore(test.ds)

	// Load the journal again. It should still get the CA journal stored on
	// disk.
	j = test.loadJournal(t)
	journalDisk = test.loadJournalFromDisk(t)
	require.NotNil(t, journalDisk)
	spiretest.RequireProtoEqual(t, j.getEntries(), journalDisk.getEntries())

	// Append a new X.509 CA, which will make the CA journal to be stored
	// on disk and in the datastore.
	now = now.Add(time.Minute)
	err = j.AppendX509CA(ctx, "C", now, &ca.X509CA{
		Signer:        kmKeys["X509-CA-C"],
		Certificate:   rootCerts["X509-Root-C"],
		UpstreamChain: testChain,
	})
	require.NoError(t, err)
	require.NoError(t, j.UpdateX509CAStatus(ctx, now, journal.Status_ACTIVE))

	journalDS = test.loadJournalFromDS(t)
	require.NotNil(t, journalDS)
	spiretest.RequireProtoEqual(t, j.getEntries(), journalDS.getEntries())
	journalDisk = test.loadJournalFromDisk(t)
	require.NotNil(t, journalDisk)
	spiretest.RequireProtoEqual(t, j.getEntries(), journalDisk.getEntries())

	// Simulate a datastore error
	dsError := errors.New("ds error")
	test.ds.SetNextError(dsError)
	err = j.AppendX509CA(ctx, "C", now, &ca.X509CA{
		Signer:        kmKeys["X509-CA-C"],
		Certificate:   rootCerts["X509-Root-C"],
		UpstreamChain: testChain,
	})
	require.Error(t, err)
	require.EqualError(t, err, "could not save CA journal in the datastore: ds error")

	// CA journal on disk should have been saved successfully
	journalDisk = test.loadJournalFromDisk(t)
	require.NotNil(t, journalDisk)
	spiretest.RequireProtoEqual(t, j.getEntries(), journalDisk.getEntries())
}

func TestAppendSetPreparedStatus(t *testing.T) {
	test := setupJournalTest(t)
	now := test.now()

	testJournal := test.loadJournal(t)

	err := testJournal.AppendX509CA(ctx, "A", now, &ca.X509CA{
		Signer:        kmKeys["X509-CA-A"],
		Certificate:   rootCerts["X509-Root-A"],
		UpstreamChain: testChain,
	})
	require.NoError(t, err)

	require.Len(t, testJournal.entries.X509CAs, 1)
	lastX509CA := testJournal.entries.X509CAs[0]
	require.Equal(t, "A", lastX509CA.SlotId)
	require.Equal(t, journal.Status_PREPARED, lastX509CA.Status)

	err = testJournal.AppendJWTKey(ctx, "B", now, &ca.JWTKey{
		Signer:   kmKeys["X509-CA-B"],
		Kid:      "KID",
		NotAfter: now.Add(time.Hour),
	})
	require.NoError(t, err)

	require.Len(t, testJournal.entries.JwtKeys, 1)
	lastJWTKey := testJournal.entries.JwtKeys[0]
	require.Equal(t, "B", lastJWTKey.SlotId)
	require.Equal(t, journal.Status_PREPARED, lastJWTKey.Status)
}

func TestX509CAOverflow(t *testing.T) {
	test := setupJournalTest(t)
	now := test.now()

	journal := test.loadJournal(t)

	for i := 0; i < (journalCap + 1); i++ {
		now = now.Add(time.Minute)
		err := journal.AppendX509CA(ctx, "A", now, &ca.X509CA{
			Signer:      kmKeys["X509-CA-A"],
			Certificate: rootCerts["X509-Root-A"],
		})
		require.NoError(t, err)
	}

	entries := journal.getEntries()
	require.Len(t, entries.X509CAs, journalCap, "X509CA entries exceeds cap")
	lastEntry := entries.X509CAs[len(entries.X509CAs)-1]
	require.Equal(t, now, time.Unix(lastEntry.IssuedAt, 0).UTC())
}

func TestUpdateX509CAStatus(t *testing.T) {
	test := setupJournalTest(t)

	firstIssuedAt := test.now()
	secondIssuedAt := firstIssuedAt.Add(time.Minute)
	thirdIssuedAt := secondIssuedAt.Add(time.Minute)

	testJournal := test.loadJournal(t)

	err := testJournal.AppendX509CA(ctx, "A", firstIssuedAt, &ca.X509CA{
		Signer:      kmKeys["X509-CA-A"],
		Certificate: rootCerts["X509-Root-A"],
	})
	require.NoError(t, err)

	err = testJournal.AppendX509CA(ctx, "B", secondIssuedAt, &ca.X509CA{
		Signer:      kmKeys["X509-CA-B"],
		Certificate: rootCerts["X509-Root-B"],
	})
	require.NoError(t, err)

	err = testJournal.AppendX509CA(ctx, "C", thirdIssuedAt, &ca.X509CA{
		Signer:      kmKeys["X509-CA-C"],
		Certificate: rootCerts["X509-Root-C"],
	})
	require.NoError(t, err)

	cas := testJournal.entries.X509CAs
	require.Len(t, cas, 3)
	for _, ca := range cas {
		require.Equal(t, journal.Status_PREPARED, ca.Status)
	}

	err = testJournal.UpdateX509CAStatus(ctx, secondIssuedAt, journal.Status_ACTIVE)
	require.NoError(t, err)

	for _, ca := range testJournal.getEntries().X509CAs {
		expectedStatus := journal.Status_PREPARED
		if ca.SlotId == "B" {
			expectedStatus = journal.Status_ACTIVE
		}

		require.Equal(t, expectedStatus, ca.Status)
	}

	unusedTime := test.now().Add(time.Hour)
	err = testJournal.UpdateX509CAStatus(ctx, unusedTime, journal.Status_OLD)
	require.ErrorContains(t, err, "no journal entry found issued at:")
}

func TestUpdateJWTKeyStatus(t *testing.T) {
	test := setupJournalTest(t)

	firstIssuedAt := test.now()
	secondIssuedAt := firstIssuedAt.Add(time.Minute)
	thirdIssuedAt := secondIssuedAt.Add(time.Minute)

	testJournal := test.loadJournal(t)

	err := testJournal.AppendJWTKey(ctx, "A", firstIssuedAt, &ca.JWTKey{
		Signer: kmKeys["JWT-Signer-A"],
		Kid:    "kid1",
	})
	require.NoError(t, err)

	err = testJournal.AppendJWTKey(ctx, "B", secondIssuedAt, &ca.JWTKey{
		Signer: kmKeys["JWT-Signer-B"],
		Kid:    "kid2",
	})
	require.NoError(t, err)

	err = testJournal.AppendJWTKey(ctx, "C", thirdIssuedAt, &ca.JWTKey{
		Signer: kmKeys["JWT-Signer-C"],
		Kid:    "kid3",
	})
	require.NoError(t, err)

	keys := testJournal.getEntries().JwtKeys
	require.Len(t, keys, 3)
	for _, key := range keys {
		require.Equal(t, journal.Status_PREPARED, key.Status)
	}

	err = testJournal.UpdateJWTKeyStatus(ctx, secondIssuedAt, journal.Status_ACTIVE)
	require.NoError(t, err)

	for _, key := range testJournal.getEntries().JwtKeys {
		expectedStatus := journal.Status_PREPARED
		if key.SlotId == "B" {
			expectedStatus = journal.Status_ACTIVE
		}

		require.Equal(t, expectedStatus, key.Status)
	}

	unusedTime := test.now().Add(time.Hour)
	err = testJournal.UpdateJWTKeyStatus(ctx, unusedTime, journal.Status_OLD)
	require.ErrorContains(t, err, "no journal entry found issued at:")
}

func TestJWTKeyOverflow(t *testing.T) {
	test := setupJournalTest(t)

	now := test.now()

	journal := test.loadJournal(t)

	for i := 0; i < (journalCap + 1); i++ {
		now = now.Add(time.Minute)
		err := journal.AppendJWTKey(ctx, "B", now, &ca.JWTKey{
			Signer:   kmKeys["JWT-Signer-B"],
			Kid:      "KID",
			NotAfter: now.Add(time.Hour),
		})
		require.NoError(t, err)
	}

	entries := journal.getEntries()
	require.Len(t, entries.JwtKeys, journalCap, "JWT key entries exceeds cap")
	lastEntry := entries.JwtKeys[len(entries.JwtKeys)-1]
	require.Equal(t, now, time.Unix(lastEntry.IssuedAt, 0).UTC())
}

func TestBadPEM(t *testing.T) {
	test := setupJournalTest(t)

	test.writeString(t, test.jc.filePath, "NOT PEM")
	_, err := LoadJournal(ctx, test.jc)
	require.EqualError(t, err, "failed to load journal from disk: invalid PEM block")
}

func TestUnexpectedPEMType(t *testing.T) {
	test := setupJournalTest(t)

	test.writeBytes(t, test.jc.filePath, pem.EncodeToMemory(&pem.Block{
		Type:  "WHATEVER",
		Bytes: []byte("FOO"),
	}))
	_, err := LoadJournal(ctx, test.jc)
	require.EqualError(t, err, `failed to load journal from disk: invalid PEM block type "WHATEVER"`)
}

func TestBadProto(t *testing.T) {
	test := setupJournalTest(t)

	test.writeBytes(t, test.jc.filePath, pem.EncodeToMemory(&pem.Block{
		Type:  journalPEMType,
		Bytes: []byte("FOO"),
	}))
	_, err := LoadJournal(ctx, test.jc)
	require.Error(t, err)
	require.Contains(t, err.Error(), `unable to unmarshal entries: `)
}

func (j *journalTest) loadJournal(t *testing.T) *Journal {
	journal, err := LoadJournal(ctx, j.jc)
	require.NoError(t, err)
	return journal
}

func (j *journalTest) loadJournalFromDisk(t *testing.T) *Journal {
	journal, err := loadJournalFromDisk(j.jc)
	require.NoError(t, err)
	return journal
}

func (j *journalTest) loadJournalFromDS(t *testing.T) *Journal {
	journal, err := loadJournalFromDS(ctx, j.jc)
	require.NoError(t, err)
	return journal
}

func (j *journalTest) writeString(t *testing.T, path, data string) {
	j.writeBytes(t, path, []byte(data))
}

func (j *journalTest) writeBytes(t *testing.T, path string, data []byte) {
	require.NoError(t, os.WriteFile(path, data, 0600))
}

func (j *journalTest) now() time.Time {
	// return truncated UTC time for cleaner failure messages
	return time.Now().UTC().Truncate(time.Second)
}

type journalTest struct {
	jc *journalConfig
	ds *fakedatastore.DataStore
}
