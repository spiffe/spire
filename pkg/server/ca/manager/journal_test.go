package manager

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/x509util"
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

	km                     keymanager.KeyManager
	kmKeys                 = map[string]keymanager.Key{}
	rootCerts              = map[string]*x509.Certificate{}
	nonExistingAuthorityID = "non-existing-authority-id"
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

		kmKeys["WIT-Signer-A"], err = km.GenerateKey(ctx, "WIT-Signer-A", keymanager.ECP256)
		require.NoError(t, err)

		kmKeys["WIT-Signer-B"], err = km.GenerateKey(ctx, "WIT-Signer-B", keymanager.ECP256)
		require.NoError(t, err)

		kmKeys["WIT-Signer-C"], err = km.GenerateKey(ctx, "WIT-Signer-C", keymanager.ECP256)
		require.NoError(t, err)
	}

	return &journalTest{
		ds: ds,
		jc: &journalConfig{
			cat: cat,
			log: log,
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

	err = j.AppendWITKey(ctx, "C", now, &ca.WITKey{
		Signer:   kmKeys["WIT-Signer-C"],
		Kid:      "kid1",
		NotAfter: now.Add(time.Hour),
	})
	require.NoError(t, err)

	authorityIDA := x509util.SubjectKeyIDToString(rootCerts["X509-Root-A"].SubjectKeyId)
	require.NoError(t, j.UpdateX509CAStatus(ctx, authorityIDA, journal.Status_ACTIVE))

	// Check that the CA journal was properly stored in the datastore.
	journalDS := test.loadJournal(t)
	require.NotNil(t, journalDS)
	spiretest.RequireProtoEqual(t, j.getEntries(), journalDS.getEntries())

	// Append a new X.509 CA, which will make the CA journal to be stored
	// on disk and in the datastore.
	now = now.Add(time.Minute)
	err = j.AppendX509CA(ctx, "C", now, &ca.X509CA{
		Signer:        kmKeys["X509-CA-C"],
		Certificate:   rootCerts["X509-Root-C"],
		UpstreamChain: testChain,
	})
	require.NoError(t, err)
	require.NoError(t, j.UpdateX509CAStatus(ctx, authorityIDA, journal.Status_ACTIVE))

	journalDS = test.loadJournal(t)
	require.NotNil(t, journalDS)
	spiretest.RequireProtoEqual(t, j.getEntries(), journalDS.getEntries())

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

	for range journalCap + 1 {
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

	authorityIDB := x509util.SubjectKeyIDToString(rootCerts["X509-Root-B"].SubjectKeyId)
	err = testJournal.UpdateX509CAStatus(ctx, authorityIDB, journal.Status_ACTIVE)
	require.NoError(t, err)

	for _, ca := range testJournal.getEntries().X509CAs {
		expectedStatus := journal.Status_PREPARED
		if ca.SlotId == "B" {
			expectedStatus = journal.Status_ACTIVE
		}

		require.Equal(t, expectedStatus, ca.Status)
	}

	err = testJournal.UpdateX509CAStatus(ctx, nonExistingAuthorityID, journal.Status_OLD)
	require.ErrorContains(t, err, fmt.Sprintf("no journal entry found with authority ID %q", nonExistingAuthorityID))
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

	err = testJournal.UpdateJWTKeyStatus(ctx, "kid2", journal.Status_ACTIVE)
	require.NoError(t, err)

	for _, key := range testJournal.getEntries().JwtKeys {
		expectedStatus := journal.Status_PREPARED
		if key.SlotId == "B" {
			expectedStatus = journal.Status_ACTIVE
		}

		require.Equal(t, expectedStatus, key.Status)
	}

	err = testJournal.UpdateJWTKeyStatus(ctx, nonExistingAuthorityID, journal.Status_OLD)
	require.ErrorContains(t, err, fmt.Sprintf("no journal entry found with authority ID %q", nonExistingAuthorityID))
}

func TestJWTKeyOverflow(t *testing.T) {
	test := setupJournalTest(t)

	now := test.now()

	journal := test.loadJournal(t)

	for range journalCap + 1 {
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

func TestUpdateWITKeyStatus(t *testing.T) {
	test := setupJournalTest(t)

	firstIssuedAt := test.now()
	secondIssuedAt := firstIssuedAt.Add(time.Minute)
	thirdIssuedAt := secondIssuedAt.Add(time.Minute)

	testJournal := test.loadJournal(t)

	err := testJournal.AppendWITKey(ctx, "A", firstIssuedAt, &ca.WITKey{
		Signer: kmKeys["WIT-Signer-A"],
		Kid:    "kid1",
	})
	require.NoError(t, err)

	err = testJournal.AppendWITKey(ctx, "B", secondIssuedAt, &ca.WITKey{
		Signer: kmKeys["WIT-Signer-B"],
		Kid:    "kid2",
	})
	require.NoError(t, err)

	err = testJournal.AppendWITKey(ctx, "C", thirdIssuedAt, &ca.WITKey{
		Signer: kmKeys["WIT-Signer-C"],
		Kid:    "kid3",
	})
	require.NoError(t, err)

	keys := testJournal.getEntries().WitKeys
	require.Len(t, keys, 3)
	for _, key := range keys {
		require.Equal(t, journal.Status_PREPARED, key.Status)
	}

	err = testJournal.UpdateWITKeyStatus(ctx, "kid2", journal.Status_ACTIVE)
	require.NoError(t, err)

	for _, key := range testJournal.getEntries().WitKeys {
		expectedStatus := journal.Status_PREPARED
		if key.SlotId == "B" {
			expectedStatus = journal.Status_ACTIVE
		}

		require.Equal(t, expectedStatus, key.Status)
	}

	err = testJournal.UpdateWITKeyStatus(ctx, nonExistingAuthorityID, journal.Status_OLD)
	require.ErrorContains(t, err, fmt.Sprintf("no journal entry found with authority ID %q", nonExistingAuthorityID))
}

func TestWITKeyOverflow(t *testing.T) {
	test := setupJournalTest(t)

	now := test.now()

	journal := test.loadJournal(t)

	for range journalCap + 1 {
		now = now.Add(time.Minute)
		err := journal.AppendWITKey(ctx, "B", now, &ca.WITKey{
			Signer:   kmKeys["WIT-Signer-B"],
			Kid:      "KID",
			NotAfter: now.Add(time.Hour),
		})
		require.NoError(t, err)
	}

	entries := journal.getEntries()
	require.Len(t, entries.WitKeys, journalCap, "WIT key entries exceeds cap")
	lastEntry := entries.WitKeys[len(entries.WitKeys)-1]
	require.Equal(t, now, time.Unix(lastEntry.IssuedAt, 0).UTC())
}

func TestBadProto(t *testing.T) {
	test := setupJournalTest(t)
	j := &Journal{
		config:                test.jc,
		activeX509AuthorityID: getOneX509AuthorityID(ctx, t, test.jc.cat.GetKeyManager()),
	}
	caJournalID, err := j.saveInDatastore(ctx, []byte("FOO"))
	require.NoError(t, err)
	require.NotZero(t, caJournalID)
	j, err = LoadJournal(ctx, test.jc)
	require.Error(t, err)
	require.Nil(t, j)
	require.Contains(t, err.Error(), `failed to load journal from datastore: unable to unmarshal entries from CA journal record:`)
}

func getOneX509AuthorityID(ctx context.Context, t *testing.T, km keymanager.KeyManager) string {
	kmKeys, err := km.GetKeys(ctx)
	require.NoError(t, err)
	subjectKeyID, err := x509util.GetSubjectKeyID(kmKeys[0].Public())
	require.NoError(t, err)
	return x509util.SubjectKeyIDToString(subjectKeyID)
}

func (j *journalTest) loadJournal(t *testing.T) *Journal {
	journal, err := LoadJournal(ctx, j.jc)
	require.NoError(t, err)
	return journal
}

func (j *journalTest) now() time.Time {
	// return truncated UTC time for cleaner failure messages
	return time.Now().UTC().Truncate(time.Second)
}

type journalTest struct {
	jc *journalConfig
	ds *fakedatastore.DataStore
}
