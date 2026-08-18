package main

import (
	"crypto"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/require"
)

func TestFileSource(t *testing.T) {
	const pollInterval = time.Second

	tempDir := t.TempDir()

	path := filepath.Join(tempDir, "file.spiffe")

	log, _ := test.NewNullLogger()
	clock := clock.NewMock(t)

	source := NewFileSource(FileSourceConfig{
		Log:          log,
		Path:         path,
		PollInterval: pollInterval,
		Clock:        clock,
	})
	defer source.Close()

	// Wait for the poll to happen and assert there is no key set available
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	_, _, ok := source.FetchKeySet()
	require.False(t, ok, "No bundle was available but we have a keyset somehow")

	// Set a bundle without an entry for the trust domain, advance to the next
	// period, wait for the poll to happen and assert there is no key set
	// available
	err := os.WriteFile(path, []byte("{}"), 0600)
	require.NoError(t, err)

	clock.Add(pollInterval)
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	_, _, ok = source.FetchKeySet()
	require.False(t, ok, "No bundle was available but we have a keyset somehow")

	// Add a bundle, step forward past the poll interval, wait for polling,
	// and assert we have a keyset.

	bundle := spiffebundle.New(spiffeid.TrustDomain{})
	err = bundle.AddJWTAuthority("KID", ec256Pubkey)
	require.NoError(t, err)
	bundleBytes, err := bundle.Marshal()
	require.NoError(t, err)
	err = os.WriteFile(path, bundleBytes, 0600)
	require.NoError(t, err)

	clock.Add(pollInterval)
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	keySet1, modTime1, ok := source.FetchKeySet()
	require.True(t, ok)
	require.Equal(t, clock.Now(), modTime1)
	require.NotNil(t, keySet1)
	require.Len(t, keySet1.Keys, 1)
	require.Equal(t, "KID", keySet1.Keys[0].KeyID)
	require.Equal(t, ec256Pubkey, keySet1.Keys[0].Key)

	// Wait another poll interval, ensure the bundle was re-fetched and that the
	// source reports no changes since nothing changed.
	clock.Add(pollInterval)
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	keySet2, modTime2, ok := source.FetchKeySet()
	require.True(t, ok)
	require.Equal(t, keySet1, keySet2)
	require.Equal(t, modTime1, modTime2)

	// Change the bundle, step forward past the poll interval, wait for polling,
	// and assert that the changes have been picked up.
	bundle = spiffebundle.New(spiffeid.TrustDomain{})
	err = bundle.AddJWTAuthority("KID2", ec256Pubkey)
	require.NoError(t, err)
	bundleBytes, err = bundle.Marshal()
	require.NoError(t, err)
	err = os.WriteFile(path, bundleBytes, 0600)
	require.NoError(t, err)

	clock.Add(pollInterval)
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	keySet3, modTime3, ok := source.FetchKeySet()
	require.True(t, ok)
	require.Equal(t, clock.Now(), modTime3)
	require.NotNil(t, keySet3)
	require.Len(t, keySet3.Keys, 1)
	require.Equal(t, "KID2", keySet3.Keys[0].KeyID)
	require.Equal(t, ec256Pubkey, keySet3.Keys[0].Key)
}

func TestFileSourceBundle(t *testing.T) {
	const pollInterval = time.Second

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := testca.New(t, td)

	path := filepath.Join(t.TempDir(), "file.spiffe")

	log, _ := test.NewNullLogger()
	clock := clock.NewMock(t)

	source := NewFileSource(FileSourceConfig{
		Log:          log,
		Path:         path,
		PollInterval: pollInterval,
		Clock:        clock,
	})
	defer source.Close()

	// Wait for the poll to happen and assert there is no bundle available
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")
	_, _, ok := source.FetchBundle()
	require.False(t, ok, "No bundle was available but we have one somehow")

	// Write out a bundle carrying both kinds of authority as well as a refresh
	// hint and a sequence number, and assert all of it survives the round trip.
	bundle := spiffebundle.New(td)
	bundle.SetX509Authorities(ca.X509Authorities())
	require.NoError(t, bundle.AddJWTAuthority("KID", ec256Pubkey))
	bundle.SetRefreshHint(10 * time.Minute)
	bundle.SetSequenceNumber(42)
	bundleBytes, err := bundle.Marshal()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, bundleBytes, 0600))

	clock.Add(pollInterval)
	clock.WaitForAfter(time.Minute, "failed to wait for the poll timer")

	actual, modTime, ok := source.FetchBundle()
	require.True(t, ok)
	require.Equal(t, clock.Now(), modTime)
	require.Equal(t, ca.X509Authorities(), actual.X509Authorities())
	require.Equal(t, map[string]crypto.PublicKey{"KID": ec256Pubkey}, actual.JWTAuthorities())

	refreshHint, ok := actual.RefreshHint()
	require.True(t, ok)
	require.Equal(t, 10*time.Minute, refreshHint)

	sequenceNumber, ok := actual.SequenceNumber()
	require.True(t, ok)
	require.Equal(t, uint64(42), sequenceNumber)
}
