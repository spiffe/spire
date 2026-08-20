package azureblob

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
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
	"google.golang.org/grpc/codes"
)

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		name string

		configureRequest      *configv1.ConfigureRequest
		newClientErr          error
		newSharedKeyClientErr error
		fetchCredentialErr    error
		expectCode            codes.Code
		expectMsg             string
		config                *Config
	}{
		{
			name: "success with service principal",
			config: &Config{
				StorageAccountName: "myaccount",
				ContainerName:      "my-container",
				BlobName:           "bundle.json",
				Format:             "spiffe",
				TenantID:           "tenant-id",
				AppID:              "app-id",
				AppSecret:          "app-secret",
			},
		},
		{
			name: "success with shared key",
			config: &Config{
				StorageAccountName: "myaccount",
				StorageAccountKey:  "dGVzdC1rZXk=",
				ContainerName:      "my-container",
				BlobName:           "bundle.json",
				Format:             "spiffe",
			},
		},
		{
			name: "success with default credential",
			config: &Config{
				StorageAccountName: "myaccount",
				ContainerName:      "my-container",
				BlobName:           "bundle.json",
				Format:             "spiffe",
			},
		},
		{
			name: "success with refresh hint",
			config: &Config{
				StorageAccountName: "myaccount",
				ContainerName:      "my-container",
				BlobName:           "bundle.json",
				Format:             "spiffe",
				RefreshHint:        "1h",
			},
		},
		{
			name: "success with custom service endpoint",
			config: &Config{
				StorageAccountName: "myaccount",
				ContainerName:      "my-container",
				BlobName:           "bundle.json",
				Format:             "spiffe",
				ServiceEndpoint:    "blob.core.usgovcloudapi.net",
			},
		},
		{
			name: "invalid service endpoint",
			config: &Config{
				StorageAccountName: "myaccount",
				ContainerName:      "my-container",
				BlobName:           "bundle.json",
				Format:             "spiffe",
				ServiceEndpoint:    "invalid host name",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "could not parse service endpoint url",
		},
		{
			name: "no storage account name",
			config: &Config{
				ContainerName: "my-container",
				BlobName:      "bundle.json",
				Format:        "spiffe",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the storage account name",
		},
		{
			name: "no container name",
			config: &Config{
				StorageAccountName: "myaccount",
				BlobName:           "bundle.json",
				Format:             "spiffe",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the container name",
		},
		{
			name: "no blob name",
			config: &Config{
				StorageAccountName: "myaccount",
				ContainerName:      "my-container",
				Format:             "spiffe",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the blob name",
		},
		{
			name: "no bundle format",
			config: &Config{
				StorageAccountName: "myaccount",
				ContainerName:      "my-container",
				BlobName:           "bundle.json",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the bundle format",
		},
		{
			name: "shared key with service principal is mutually exclusive",
			config: &Config{
				StorageAccountName: "myaccount",
				StorageAccountKey:  "dGVzdC1rZXk=",
				ContainerName:      "my-container",
				BlobName:           "bundle.json",
				Format:             "spiffe",
				TenantID:           "tenant-id",
				AppID:              "app-id",
				AppSecret:          "app-secret",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "storage account key and client secret credentials are mutually exclusive",
		},
		{
			name: "shared key client error",
			config: &Config{
				StorageAccountName: "myaccount",
				StorageAccountKey:  "dGVzdC1rZXk=",
				ContainerName:      "my-container",
				BlobName:           "bundle.json",
				Format:             "spiffe",
			},
			expectCode:            codes.Internal,
			expectMsg:             "failed to create client: shared key client error",
			newSharedKeyClientErr: errors.New("shared key client error"),
		},
		{
			name: "missing tenant id with partial service principal config",
			config: &Config{
				StorageAccountName: "myaccount",
				ContainerName:      "my-container",
				BlobName:           "bundle.json",
				Format:             "spiffe",
				AppID:              "app-id",
				AppSecret:          "app-secret",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the tenant ID",
		},
		{
			name: "missing app id with partial service principal config",
			config: &Config{
				StorageAccountName: "myaccount",
				ContainerName:      "my-container",
				BlobName:           "bundle.json",
				Format:             "spiffe",
				TenantID:           "tenant-id",
				AppSecret:          "app-secret",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the app ID",
		},
		{
			name: "missing app secret with partial service principal config",
			config: &Config{
				StorageAccountName: "myaccount",
				ContainerName:      "my-container",
				BlobName:           "bundle.json",
				Format:             "spiffe",
				TenantID:           "tenant-id",
				AppID:              "app-id",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the app secret",
		},
		{
			name: "client error",
			config: &Config{
				StorageAccountName: "myaccount",
				ContainerName:      "my-container",
				BlobName:           "bundle.json",
				Format:             "spiffe",
			},
			expectCode:   codes.Internal,
			expectMsg:    "failed to create client: client creation error",
			newClientErr: errors.New("client creation error"),
		},
		{
			name: "fetch credential error",
			config: &Config{
				StorageAccountName: "myaccount",
				ContainerName:      "my-container",
				BlobName:           "bundle.json",
				Format:             "spiffe",
			},
			expectCode:         codes.Internal,
			expectMsg:          "unable to fetch default credential: credential error",
			fetchCredentialErr: errors.New("credential error"),
		},
		{
			name: "invalid refresh hint",
			config: &Config{
				StorageAccountName: "myaccount",
				ContainerName:      "my-container",
				BlobName:           "bundle.json",
				Format:             "spiffe",
				RefreshHint:        "invalid-refresh-hint",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "could not parse refresh_hint: could not parse refresh hint \"invalid-refresh-hint\": time: invalid duration \"invalid-refresh-hint\"",
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

			newClient := func(cred azcore.TokenCredential, accountURL string) (blobStorage, error) {
				if tt.newClientErr != nil {
					return nil, tt.newClientErr
				}
				return &fakeClient{}, nil
			}
			p := newPlugin(newClient)
			p.hooks.newBlobClientSharedKeyFunc = func(accountURL string, cred *azblob.SharedKeyCredential) (blobStorage, error) {
				if tt.newSharedKeyClientErr != nil {
					return nil, tt.newSharedKeyClientErr
				}
				return &fakeClient{}, nil
			}
			p.hooks.fetchCredential = func() (azcore.TokenCredential, error) {
				if tt.fetchCredentialErr != nil {
					return nil, tt.fetchCredentialErr
				}
				return &fakeCredential{}, nil
			}

			plugintest.Load(t, builtin(p), nil, options...)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsg)

			if tt.expectMsg != "" {
				require.Nil(t, p.config)
				return
			}

			tt.config.bundleFormat, err = bundleformat.FromString(tt.config.Format)
			require.NoError(t, err)

			if tt.config.RefreshHint != "" {
				refreshDuration, err := time.ParseDuration(tt.config.RefreshHint)
				if err == nil {
					tt.config.parsedRefreshHint = int64(refreshDuration.Seconds())
				}
			}

			serviceEndpoint := tt.config.ServiceEndpoint
			if serviceEndpoint == "" {
				serviceEndpoint = "blob.core.windows.net"
			}
			tt.config.accountURL = fmt.Sprintf("https://%s.%s", tt.config.StorageAccountName, serviceEndpoint)

			require.Equal(t, tt.config, p.config)
		})
	}
}

func TestPublishBundle(t *testing.T) {
	testBundle := getTestBundle(t)

	for _, tt := range []struct {
		name string

		expectCode      codes.Code
		expectMsg       string
		config          *Config
		bundle          *types.Bundle
		uploadBufferErr error
	}{
		{
			name:   "success",
			bundle: testBundle,
			config: &Config{
				StorageAccountName: "myaccount",
				ContainerName:      "my-container",
				BlobName:           "bundle.json",
				Format:             "spiffe",
			},
		},
		{
			name:   "upload failure",
			bundle: testBundle,
			config: &Config{
				StorageAccountName: "myaccount",
				ContainerName:      "my-container",
				BlobName:           "bundle.json",
				Format:             "spiffe",
			},
			uploadBufferErr: errors.New("some error"),
			expectCode:      codes.Internal,
			expectMsg:       "failed to upload blob: some error",
		},
		{
			name:       "not configured",
			expectCode: codes.FailedPrecondition,
			expectMsg:  "not configured",
		},
		{
			name: "missing bundle",
			config: &Config{
				StorageAccountName: "myaccount",
				ContainerName:      "my-container",
				BlobName:           "bundle.json",
				Format:             "spiffe",
			},
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
				plugintest.ConfigureJSON(tt.config),
			}

			newClient := func(cred azcore.TokenCredential, accountURL string) (blobStorage, error) {
				return &fakeClient{
					t:                   t,
					expectContainerName: tt.config.ContainerName,
					expectBlobName:      tt.config.BlobName,
					uploadBufferErr:     tt.uploadBufferErr,
				}, nil
			}
			p := newPlugin(newClient)
			p.hooks.fetchCredential = func() (azcore.TokenCredential, error) {
				return &fakeCredential{}, nil
			}

			if tt.config != nil {
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
		StorageAccountName: "myaccount",
		ContainerName:      "my-container",
		BlobName:           "bundle.json",
		Format:             "spiffe",
	}

	var err error
	options := []plugintest.Option{
		plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.ConfigureJSON(config),
	}

	newClient := func(cred azcore.TokenCredential, accountURL string) (blobStorage, error) {
		return &fakeClient{
			t:                   t,
			expectContainerName: config.ContainerName,
			expectBlobName:      config.BlobName,
		}, nil
	}
	p := newPlugin(newClient)
	p.hooks.fetchCredential = func() (azcore.TokenCredential, error) {
		return &fakeCredential{}, nil
	}
	plugintest.Load(t, builtin(p), nil, options...)
	require.NoError(t, err)

	bundle := getTestBundle(t)
	bundle.SequenceNumber = 1

	client, ok := p.blobClient.(*fakeClient)
	require.True(t, ok)

	client.uploadBufferCount = 0
	resp, err := p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 1, client.uploadBufferCount)

	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 1, client.uploadBufferCount)

	bundle = getTestBundle(t)
	bundle.SequenceNumber = 2
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 2, client.uploadBufferCount)

	client.uploadBufferErr = errors.New("error calling UploadBuffer")

	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 2, client.uploadBufferCount)

	bundle = getTestBundle(t)
	bundle.SequenceNumber = 3
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.Error(t, err)
	require.Nil(t, resp)
	require.Equal(t, 2, client.uploadBufferCount)

	client.uploadBufferErr = nil
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 3, client.uploadBufferCount)
}

func TestSetRefreshHint(t *testing.T) {
	config := &Config{
		StorageAccountName: "myaccount",
		ContainerName:      "my-container",
		BlobName:           "bundle.json",
		Format:             "spiffe",
		RefreshHint:        "1h",
	}

	var err error
	options := []plugintest.Option{
		plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.ConfigureJSON(config),
	}

	client := &fakeClient{t: t, expectContainerName: config.ContainerName, expectBlobName: config.BlobName}
	newClient := func(cred azcore.TokenCredential, accountURL string) (blobStorage, error) {
		return client, nil
	}
	p := newPlugin(newClient)
	p.hooks.fetchCredential = func() (azcore.TokenCredential, error) {
		return &fakeCredential{}, nil
	}
	plugintest.Load(t, builtin(p), nil, options...)
	require.NoError(t, err)

	bundle := getTestBundle(t)
	resp, err := p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	publishedBundle, err := bundleutil.Decode(spiffeid.RequireTrustDomainFromString("example.org"), bytes.NewReader(client.writtenBytes))
	require.NoError(t, err)
	refreshHint, ok := publishedBundle.RefreshHint()
	require.True(t, ok)
	require.Equal(t, time.Hour, refreshHint)
}

func TestBundleWithRefreshHintPublishedOnce(t *testing.T) {
	config := &Config{
		StorageAccountName: "myaccount",
		ContainerName:      "my-container",
		BlobName:           "bundle.json",
		Format:             "spiffe",
		RefreshHint:        "1h",
	}

	var err error
	options := []plugintest.Option{
		plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.ConfigureJSON(config),
	}

	client := &fakeClient{t: t, expectContainerName: config.ContainerName, expectBlobName: config.BlobName}
	newClient := func(cred azcore.TokenCredential, accountURL string) (blobStorage, error) {
		return client, nil
	}
	p := newPlugin(newClient)
	p.hooks.fetchCredential = func() (azcore.TokenCredential, error) {
		return &fakeCredential{}, nil
	}
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

	require.Equal(t, 1, client.uploadBufferCount)
}

type fakeCredential struct{}

func (f *fakeCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, nil
}

type fakeClient struct {
	t *testing.T

	uploadBufferErr     error
	expectContainerName string
	expectBlobName      string
	uploadBufferCount   int
	writtenBytes        []byte
}

func (c *fakeClient) UploadBuffer(_ context.Context, containerName string, blobName string, buffer []byte, _ *azblob.UploadBufferOptions) (azblob.UploadBufferResponse, error) {
	if c.uploadBufferErr != nil {
		return azblob.UploadBufferResponse{}, c.uploadBufferErr
	}

	require.Equal(c.t, c.expectContainerName, containerName, "container name mismatch")
	require.Equal(c.t, c.expectBlobName, blobName, "blob name mismatch")

	c.writtenBytes = make([]byte, len(buffer))
	copy(c.writtenBytes, buffer)

	c.uploadBufferCount++
	return azblob.UploadBufferResponse{}, nil
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
