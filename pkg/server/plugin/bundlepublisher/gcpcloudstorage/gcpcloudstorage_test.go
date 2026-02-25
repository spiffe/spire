package gcpcloudstorage

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"testing"
	"time"

	"cloud.google.com/go/storage"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk/support/bundleformat"
	bundlepublisherv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/bundlepublisher/v1"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
)

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		name string

		configureRequest *configv1.ConfigureRequest
		newClientErr     error
		expectCode       codes.Code
		expectMsg        string
		config           *Config
	}{
		{
			name: "success",
			config: &Config{
				ServiceAccountFile: "service-account-file",
				BucketName:         "bucket-name",
				ObjectName:         "object-name",
				Format:             "spiffe",
			},
		},
		{
			name: "success with refresh hint",
			config: &Config{
				ServiceAccountFile: "service-account-file",
				BucketName:         "bucket-name",
				ObjectName:         "object-name",
				Format:             "spiffe",
				RefreshHint:        "1h",
			},
		},
		{
			name: "no bucket",
			config: &Config{
				ObjectName: "object-name",
				Format:     "spiffe",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the bucket name",
		},
		{
			name: "no object name",
			config: &Config{
				BucketName: "bucket-name",
				Format:     "spiffe",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the object name",
		},
		{
			name: "no bundle format",
			config: &Config{
				ObjectName: "object-name",
				BucketName: "bucket-name",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the bundle format",
		},
		{
			name: "invalid refresh hint",
			config: &Config{
				ObjectName:  "object-name",
				BucketName:  "bucket-name",
				Format:      "spiffe",
				RefreshHint: "invalid-refresh-hint",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "could not parse refresh_hint: could not parse refresh hint \"invalid-refresh-hint\": time: invalid duration \"invalid-refresh-hint\"",
		},
		{
			name: "client error",
			config: &Config{
				ServiceAccountFile: "service-account-file",
				BucketName:         "bucket-name",
				ObjectName:         "object-name",
				Format:             "spiffe",
			},
			expectCode:   codes.Internal,
			expectMsg:    "failed to create client: client creation error",
			newClientErr: errors.New("client creation error"),
		},
		{
			name: "invalid format",
			config: &Config{
				BucketName: "bucket-name",
				ObjectName: "object-name",
				Format:     "invalid-format",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "could not parse bundle format from configuration: unknown bundle format: \"invalid-format\"",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
				plugintest.ConfigureJSON(tt.config),
			}

			newClient := func(ctx context.Context, opts ...option.ClientOption) (gcsService, error) {
				if tt.newClientErr != nil {
					return nil, tt.newClientErr
				}
				return &fakeClient{
					clientOptions: opts,
				}, nil
			}

			newStorageWriter := func(ctx context.Context, o *storage.ObjectHandle) io.WriteCloser {
				return &fakeStorageWriter{}
			}
			p := newPlugin(newClient, newStorageWriter)

			plugintest.Load(t, builtin(p), nil, options...)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsg)

			if tt.expectMsg != "" {
				require.Nil(t, p.config)
				return
			}

			// Check that the plugin has the expected configuration.
			tt.config.bundleFormat, err = bundleformat.FromString(tt.config.Format)
			require.NoError(t, err)

			if tt.config.RefreshHint != "" {
				refreshDuration, err := time.ParseDuration(tt.config.RefreshHint)
				if err == nil {
					tt.config.parsedRefreshHint = int64(refreshDuration.Seconds())
				}
			}

			require.Equal(t, tt.config, p.config)

			client, ok := p.gcsClient.(*fakeClient)
			require.True(t, ok)

			// It's important to check that the configuration has been wired
			// up to the gcs config, that needs to have the specified service
			// account file.
			require.Equal(t, []option.ClientOption{option.WithAuthCredentialsFile(option.ServiceAccount, tt.config.ServiceAccountFile)}, client.clientOptions)
		})
	}
}

func TestPublishBundle(t *testing.T) {
	testBundle := getTestBundle(t)
	config := &Config{
		BucketName: "bucket-name",
		ObjectName: "object-name",
		Format:     "spiffe",
	}

	for _, tt := range []struct {
		name string

		newClientErr error
		expectCode   codes.Code
		expectMsg    string
		noConfig     bool
		bundle       *types.Bundle
		writeErr     error
		closeErr     error
	}{
		{
			name:   "success",
			bundle: testBundle,
		},
		{
			name:   "multiple times",
			bundle: testBundle,
		},
		{
			name:       "write failure",
			bundle:     testBundle,
			writeErr:   errors.New("write error"),
			expectCode: codes.Internal,
			expectMsg:  "failed to write bundle: write error",
		},
		{
			name:       "close failure",
			bundle:     testBundle,
			closeErr:   errors.New("close error"),
			expectCode: codes.Internal,
			expectMsg:  "failed to close storage writer: close error",
		},
		{
			name:       "not configured",
			noConfig:   true,
			expectCode: codes.FailedPrecondition,
			expectMsg:  "not configured",
		},
		{
			name:       "missing bundle",
			expectCode: codes.InvalidArgument,
			expectMsg:  "missing bundle in request",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
				plugintest.ConfigureJSON(config),
			}

			newClient := func(ctx context.Context, opts ...option.ClientOption) (gcsService, error) {
				return &fakeClient{
					clientOptions: opts,
				}, nil
			}

			newStorageWriter := func(ctx context.Context, o *storage.ObjectHandle) io.WriteCloser {
				return &fakeStorageWriter{
					writeErr: tt.writeErr,
					closeErr: tt.closeErr,
				}
			}
			p := newPlugin(newClient, newStorageWriter)

			if !tt.noConfig {
				plugintest.Load(t, builtin(p), nil, options...)
				require.NoError(t, err)
			}

			resp, err := p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
				Bundle: tt.bundle,
			})

			if tt.expectMsg != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
		})
	}
}

func TestPublishMultiple(t *testing.T) {
	config := &Config{
		BucketName: "bucket-name",
		ObjectName: "object-name",
		Format:     "spiffe",
	}

	var err error
	options := []plugintest.Option{
		plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.ConfigureJSON(config),
	}

	newClient := func(ctx context.Context, opts ...option.ClientOption) (gcsService, error) {
		return &fakeClient{
			clientOptions: opts,
		}, nil
	}
	newStorageWriter := getFakeNewStorageWriterFunc(nil, nil)
	p := newPlugin(newClient, newStorageWriter)

	var testWriteObjectCount int
	p.hooks.wroteObjectFunc = func() { testWriteObjectCount++ }
	plugintest.Load(t, builtin(p), nil, options...)
	require.NoError(t, err)

	// Test multiple write operations, and check that only a call to Write is
	// done when there is a modified bundle that was not successfully published
	// before.

	// Have an initial bundle with SequenceNumber = 1.
	bundle := getTestBundle(t)
	bundle.SequenceNumber = 1

	// Reset the testWriteObjectCount counter.
	testWriteObjectCount = 0
	resp, err := p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 1, testWriteObjectCount)

	// Call PublishBundle with the same bundle.
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// The same bundle was used, the testWriteObjectCount counter should be still 1.
	require.Equal(t, 1, testWriteObjectCount)

	// Have a new bundle and call PublishBundle.
	bundle = getTestBundle(t)
	bundle.SequenceNumber = 2
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// PublishBundle was called with a different bundle, testWriteObjectCount should
	// be incremented to be 2.
	require.Equal(t, 2, testWriteObjectCount)

	// Simulate that there is an error writing to the storage.
	p.hooks.newStorageWriterFunc = getFakeNewStorageWriterFunc(errors.New("write error"), nil)

	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	// Since there is no change in the bundle, Write should not be called
	// and there should be no error.
	require.NoError(t, err)
	require.NotNil(t, resp)

	// The same bundle was used, the testWriteObjectCount counter should be still 2.
	require.Equal(t, 2, testWriteObjectCount)

	// Have a new bundle and call PublishBundle. Write should be called this
	// time and return an error.
	bundle = getTestBundle(t)
	bundle.SequenceNumber = 3
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.Error(t, err)
	require.Nil(t, resp)

	// Since the bundle could not be published, testWriteObjectCount should be
	// still 2.
	require.Equal(t, 2, testWriteObjectCount)

	// Clear the Write error and call PublishBundle.
	p.hooks.newStorageWriterFunc = getFakeNewStorageWriterFunc(nil, nil)
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})

	// No error should happen this time.
	require.NoError(t, err)
	require.NotNil(t, resp)

	// The testWriteObjectCount counter should be incremented to 3, since the bundle
	// should have been published successfully.
	require.Equal(t, 3, testWriteObjectCount)
}

func TestSetRefreshHint(t *testing.T) {
	config := &Config{
		BucketName:  "bucket-name",
		ObjectName:  "object-name",
		Format:      "spiffe",
		RefreshHint: "1h",
	}

	var err error
	options := []plugintest.Option{
		plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.ConfigureJSON(config),
	}

	newClient := func(ctx context.Context, opts ...option.ClientOption) (gcsService, error) {
		return &fakeClient{
			clientOptions: opts,
		}, nil
	}

	storageWriter := &fakeStorageWriter{}
	p := newPlugin(newClient, func(ctx context.Context, o *storage.ObjectHandle) io.WriteCloser {
		return storageWriter
	})

	plugintest.Load(t, builtin(p), nil, options...)
	require.NoError(t, err)

	bundle := getTestBundle(t)
	resp, err := p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	publishedBundle, err := bundleutil.Decode(spiffeid.RequireTrustDomainFromString("example.org"), bytes.NewReader(storageWriter.writtenBytes))
	require.NoError(t, err)
	refreshHint, ok := publishedBundle.RefreshHint()
	require.True(t, ok)
	require.Equal(t, time.Hour, refreshHint)
}

// If the refresh hint is set, the bundle we publish is different from the one we received.
// Makes sure we don't republish an unchanged bundle if we have set the refresh hint.
func TestBundleWithRefreshHintPublishedOnce(t *testing.T) {
	config := &Config{
		BucketName:  "bucket-name",
		ObjectName:  "object-name",
		Format:      "spiffe",
		RefreshHint: "1h",
	}

	var err error
	options := []plugintest.Option{
		plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.ConfigureJSON(config),
	}

	newClient := func(ctx context.Context, opts ...option.ClientOption) (gcsService, error) {
		return &fakeClient{
			clientOptions: opts,
		}, nil
	}

	storageWriter := &fakeStorageWriter{}
	p := newPlugin(newClient, func(ctx context.Context, o *storage.ObjectHandle) io.WriteCloser {
		return storageWriter
	})

	var testWriteObjectCount int
	p.hooks.wroteObjectFunc = func() { testWriteObjectCount++ }
	plugintest.Load(t, builtin(p), nil, options...)
	require.NoError(t, err)

	bundle := getTestBundle(t)
	resp, err := p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	require.Equal(t, 1, testWriteObjectCount)
}

type fakeClient struct {
	clientOptions []option.ClientOption
}

func (c *fakeClient) Bucket(string) *storage.BucketHandle {
	return &storage.BucketHandle{}
}

func (c *fakeClient) Close() error {
	return nil
}

type fakeStorageWriter struct {
	writeErr     error
	closeErr     error
	writtenBytes []byte
}

func (s *fakeStorageWriter) Write(p []byte) (n int, err error) {
	if s.writeErr == nil {
		s.writtenBytes = make([]byte, len(p))
		copy(s.writtenBytes, p)
		return len(p), nil
	}
	return 0, s.writeErr
}

func (s *fakeStorageWriter) Close() error {
	return s.closeErr
}

func getFakeNewStorageWriterFunc(writeErr, closeErr error) func(ctx context.Context, o *storage.ObjectHandle) io.WriteCloser {
	return func(ctx context.Context, o *storage.ObjectHandle) io.WriteCloser {
		return &fakeStorageWriter{
			writeErr: writeErr,
			closeErr: closeErr,
		}
	}
}

func getTestBundle(t *testing.T) *types.Bundle {
	cert, _, err := util.LoadCAFixture()
	require.NoError(t, err)

	keyPkix, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	require.NoError(t, err)

	return &types.Bundle{
		TrustDomain:     "example.org",
		X509Authorities: []*types.X509Certificate{{Asn1: cert.Raw}},
		JwtAuthorities: []*types.JWTKey{
			{
				KeyId:     "KID",
				PublicKey: keyPkix,
			},
		},
		RefreshHint:    1440,
		SequenceNumber: 100,
	}
}
