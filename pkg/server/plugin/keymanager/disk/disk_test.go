package disk

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/base"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/test"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/keymanager"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

var (
	ctx = context.Background()
)

func TestKeyManager(t *testing.T) {
	suite.Run(t, new(Suite))
}

type Suite struct {
	suite.Suite

	tmpDir string
	m      *KeyManager
}

func (s *Suite) SetupTest() {
	// initialize a temp directory and a subdirectory within (to aid with
	// persistence failure testing)
	var err error
	s.tmpDir, err = ioutil.TempDir("", "server-keymanager-disk-")
	s.Require().NoError(err)
	s.Require().NoError(os.MkdirAll(s.keysDir(), 0755))
	s.createManager()
}

func (s *Suite) TearDownTest() {
	os.RemoveAll(s.tmpDir)
}

func (s *Suite) createManager() {
	s.m = New()
	resp, err := s.m.Configure(ctx, &plugin.ConfigureRequest{
		Configuration: fmt.Sprintf("keys_path = %q", s.keysPath()),
	})
	s.Require().NoError(err)
	s.Require().Equal(&plugin.ConfigureResponse{}, resp)
}

func (s *Suite) keysDir() string {
	return filepath.Join(s.tmpDir, "keys")
}

func (s *Suite) keysPath() string {
	return filepath.Join(s.keysDir(), "keys.json")
}

func (s *Suite) TestGeneralFunctionality() {
	test.Run(s.T(), func(t *testing.T) catalog.Plugin {
		caseDir, err := ioutil.TempDir(s.tmpDir, "testcase-")
		require.NoError(t, err)

		m := New()
		resp, err := m.Configure(context.Background(), &plugin.ConfigureRequest{
			Configuration: fmt.Sprintf("keys_path = %q", filepath.Join(caseDir, "keys.json")),
		})
		require.NoError(t, err)
		require.Equal(t, &plugin.ConfigureResponse{}, resp)
		return builtin(m)
	})
}

func (s *Suite) TestConfigureMissingPath() {
	m := New()
	resp, err := m.Configure(ctx, &plugin.ConfigureRequest{})
	s.Require().EqualError(err, "keymanager(disk): keys_path is required")
	s.Require().Nil(resp)
}

func (s *Suite) TestGenerateKeyBeforeConfigure() {
	m := New()
	resp, err := m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   "KEY",
		KeyType: keymanager.KeyType_EC_P256,
	})
	s.Require().EqualError(err, "keymanager(disk): not configured")
	s.Require().Nil(resp)
}

func (s *Suite) TestGenerateKeyPersistenceFailure() {
	s.Require().NoError(os.Remove(s.keysDir()))
	resp, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   "KEY",
		KeyType: keymanager.KeyType_EC_P256,
	})
	s.Require().Error(err)
	s.Require().Contains(err.Error(), "keymanager(disk): unable to write entries")
	s.Require().Nil(resp)

	// make sure key doesn't exist when it couldn't be saved to disk
	getResp, err := s.m.GetPublicKey(ctx, &keymanager.GetPublicKeyRequest{
		KeyId: "KEY",
	})
	s.Require().NoError(err)
	s.Require().Nil(getResp.PublicKey)

	// now create the directory so the key can be persisted
	s.Require().NoError(os.Mkdir(s.keysDir(), 0755))

	// generate and persist the key
	resp, err = s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   "KEY",
		KeyType: keymanager.KeyType_EC_P256,
	})
	s.Require().NoError(err)

	// now remove the directory and try to override the key. the original key
	// should remain intact after the generate call fails.
	s.Require().NoError(os.RemoveAll(s.keysDir()))
	_, err = s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   "KEY",
		KeyType: keymanager.KeyType_EC_P256,
	})
	s.Require().Error(err)

	getResp, err = s.m.GetPublicKey(ctx, &keymanager.GetPublicKeyRequest{
		KeyId: "KEY",
	})
	s.Require().NoError(err)
	s.Require().Equal(resp.PublicKey, getResp.PublicKey)
}

func (s *Suite) TestGenerateKeyPersistence() {
	resp1, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   "KEY1",
		KeyType: keymanager.KeyType_EC_P256,
	})
	s.Require().NoError(err)

	resp2, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   "KEY2",
		KeyType: keymanager.KeyType_EC_P384,
	})
	s.Require().NoError(err)

	// make sure keys have been saved
	entries, err := loadEntries(s.keysPath())
	s.Require().NoError(err)
	base.SortKeyEntries(entries)
	s.Require().Len(entries, 2)
	s.Require().Equal(resp1.PublicKey, entries[0].PublicKey)
	s.Require().Equal(resp2.PublicKey, entries[1].PublicKey)

	// recreate key manager and make sure keys were loaded
	s.createManager()
	resp, err := s.m.GetPublicKeys(ctx, &keymanager.GetPublicKeysRequest{})
	s.Require().NoError(err)
	s.Require().Len(resp.PublicKeys, 2)
	s.Require().Equal(resp1.PublicKey, resp.PublicKeys[0])
	s.Require().Equal(resp2.PublicKey, resp.PublicKeys[1])
}

func (s *Suite) TestGetPluginInfo() {
	resp, err := s.m.GetPluginInfo(ctx, &plugin.GetPluginInfoRequest{})
	s.Require().NoError(err)
	s.Require().Equal(&plugin.GetPluginInfoResponse{}, resp)
}
