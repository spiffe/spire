package disk

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	svidstorev1 "github.com/spiffe/spire/proto/spire/plugin/agent/svidstore/v1"
	"go.uber.org/multierr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "disk"
	attrName   = "spire-svid"
)

type certFile struct {
	filePath string
	pemBytes []byte
}

type diskStore struct {
	certChain certFile
	key       certFile
	bundle    certFile
}

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *DiskPlugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		svidstorev1.SVIDStorePluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

func New() *DiskPlugin {
	return &DiskPlugin{}
}

type configuration struct {
	Directory string `hcl:"directory" json:"directory"`
}

type DiskPlugin struct {
	svidstorev1.UnsafeSVIDStoreServer
	configv1.UnsafeConfigServer

	log         hclog.Logger
	config      *configuration
	trustDomain string
	mtx         sync.RWMutex
}

// SetLogger sets the logger used by the plugin
func (p *DiskPlugin) SetLogger(log hclog.Logger) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.log = log
}

// Configure configures the plugin
func (p *DiskPlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := &configuration{}
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.trustDomain = req.CoreConfiguration.TrustDomain
	p.config = config
	if config.Directory == "" {
		return nil, status.Error(codes.InvalidArgument, "a directory must be configured")
	}

	return &configv1.ConfigureResponse{}, nil
}

// PutX509SVID stores the specified X509-SVID in the configured location
func (p *DiskPlugin) PutX509SVID(ctx context.Context, req *svidstorev1.PutX509SVIDRequest) (*svidstorev1.PutX509SVIDResponse, error) {
	log := p.log.With(telemetry.SPIFFEID, req.Svid.SpiffeID)

	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	diskStore, err := newDiskStore(req.Metadata, config.Directory)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	diskStore.certChain.pemBytes = certChainPEMBytes(req.Svid.CertChain)
	diskStore.key.pemBytes = keyPEMBytes(req.Svid.PrivateKey)
	diskStore.bundle.pemBytes = certChainPEMBytes(req.Svid.Bundle)

	log.With("cert_chain_file_path", diskStore.certChain.filePath).Debug("Writing certificate chain file")
	if err := diskStore.certChain.write(p.trustDomain); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to write certificate chain file: %v", err)
	}

	log.With("key_file_path", diskStore.key.filePath).Debug("Writing key file")
	if err := diskStore.key.write(p.trustDomain); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to write key file: %v", err)
	}

	log.With("bundle_file_path", diskStore.bundle.filePath).Debug("Writing bundle file")
	if err := diskStore.bundle.write(p.trustDomain); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to write bundle file: %v", err)
	}

	return &svidstorev1.PutX509SVIDResponse{}, nil
}

// DeleteX509SVID deletes the specified stored X509-SVID
func (p *DiskPlugin) DeleteX509SVID(ctx context.Context, req *svidstorev1.DeleteX509SVIDRequest) (*svidstorev1.DeleteX509SVIDResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}
	diskStore, err := newDiskStore(req.Metadata, config.Directory)
	if err != nil {
		return nil, err
	}

	if errRemoveCertChain := diskStore.certChain.delete(); errRemoveCertChain != nil {
		if os.IsNotExist(errRemoveCertChain) {
			p.log.With("file_path", diskStore.certChain.filePath).Warn("Could not delete certificate chain file. File not found")
		} else {
			err = multierr.Append(err, fmt.Errorf("failed to delete certificate chain file: %w", errRemoveCertChain))
		}
	}
	if errRemoveKey := diskStore.key.delete(); errRemoveKey != nil {
		if os.IsNotExist(errRemoveKey) {
			p.log.With("file_path", diskStore.key.filePath).Warn("Could not delete key file. File not found")
		} else {
			err = multierr.Append(err, fmt.Errorf("failed to delete key file: %w", errRemoveKey))
		}
	}
	if errRemoveBundle := diskStore.bundle.delete(); errRemoveBundle != nil {
		if os.IsNotExist(errRemoveBundle) {
			p.log.With("file_path", diskStore.bundle.filePath).Warn("Could not delete bundle file. File not found")
		} else {
			err = multierr.Append(err, fmt.Errorf("failed to delete bundle file: %w", errRemoveBundle))
		}
	}

	if err != nil {
		return nil, status.Errorf(codes.Internal, "error deleting SVID: %v", err)
	}

	return &svidstorev1.DeleteX509SVIDResponse{}, nil
}

func (p *DiskPlugin) getConfig() (*configuration, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func (c *certFile) write(attrValue string) error {
	if err := validateXattr(c.filePath, attrValue); err != nil {
		return err
	}

	if err := createBaseDirectoryIfNeeded(c.filePath); err != nil {
		return err
	}

	if err := diskutil.AtomicWriteFile(c.filePath, c.pemBytes, 0600); err != nil {
		return err
	}
	if err := setxattr(c.filePath, attrName, []byte(attrValue)); err != nil {
		return fmt.Errorf("failed to set extended attribute to file: %w", err)
	}

	return nil
}

func (c *certFile) delete() error {
	return os.Remove(c.filePath)
}

func getFileMetadata(metadataMap map[string]string, key string) (string, error) {
	value := metadataMap[key]
	if value == "" {
		return "", status.Errorf(codes.InvalidArgument, "%s must be specified", key)
	}
	if containsDotDot(value) {
		return "", status.Errorf(codes.InvalidArgument, "invalid %s", key)
	}

	return value, nil
}

func newDiskStore(metaData []string, dir string) (*diskStore, error) {
	metadataMap, err := svidstore.ParseMetadata(metaData)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error parsing metadata: %v", err)
	}

	certChainFilePath, err := getFileMetadata(metadataMap, "certchainfile")
	if err != nil {
		return nil, err
	}

	keyFilePath, err := getFileMetadata(metadataMap, "keyfile")
	if err != nil {
		return nil, err
	}

	bundleFilePath, err := getFileMetadata(metadataMap, "bundlefile")
	if err != nil {
		return nil, err
	}

	return &diskStore{
		certChain: certFile{filePath: filepath.Join(dir, certChainFilePath)},
		key:       certFile{filePath: filepath.Join(dir, keyFilePath)},
		bundle:    certFile{filePath: filepath.Join(dir, bundleFilePath)},
	}, nil
}

// validateXattr validates that the specified file has
// an extended attribute (https://en.wikipedia.org/wiki/Extended_file_attributes)
// set by this plugin, with the trust domain as the value.
// This is a best-effort attempt to avoid collisions with other systems.
// Some platforms do not support this mechanism.
func validateXattr(filePath, attrValue string) error {
	if _, statErr := os.Stat(filePath); os.IsNotExist(statErr) {
		return nil
	}

	dest := make([]byte, len(attrValue))
	err := getxattr(filePath, attrName, dest)
	if err != nil {
		return fmt.Errorf("validation error: %w", err)
	}
	if string(dest) != attrValue {
		return errors.New("validation error: attribute mismatch")
	}

	return nil
}

func keyPEMBytes(privateKey []byte) (pemData []byte) {
	b := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKey,
	}

	return pem.EncodeToMemory(b)
}

func certChainPEMBytes(certChain [][]byte) (pemData []byte) {
	for _, cert := range certChain {
		b := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		}
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	return pemData
}

func createBaseDirectoryIfNeeded(filePath string) error {
	baseDir := filepath.Dir(filePath)
	if _, statErr := os.Stat(baseDir); os.IsNotExist(statErr) {
		if err := os.MkdirAll(baseDir, 0755); err != nil {
			return status.Errorf(codes.Internal, "error creating directory: %v", err)
		}
	}
	return nil
}

func containsDotDot(v string) bool {
	if !strings.Contains(v, "..") {
		return false
	}
	for _, ent := range strings.FieldsFunc(v, isSlashRune) {
		if ent == ".." {
			return true
		}
	}
	return false
}

func isSlashRune(r rune) bool { return r == '/' || r == '\\' }
