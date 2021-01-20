package sdsv3

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secret_v3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	tdBundle = bundleutil.BundleFromRootCA("spiffe://domain.test", &x509.Certificate{
		Raw: []byte("BUNDLE"),
	})
	tdValidationContext = &tls_v3.Secret{
		Name: "spiffe://domain.test",
		Type: &tls_v3.Secret_ValidationContext{
			ValidationContext: &tls_v3.CertificateValidationContext{
				TrustedCa: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: []byte("-----BEGIN CERTIFICATE-----\nQlVORExF\n-----END CERTIFICATE-----\n"),
					},
				},
			},
		},
	}

	tdValidationContext2 = &tls_v3.Secret{
		Name: "ROOTCA",
		Type: &tls_v3.Secret_ValidationContext{
			ValidationContext: &tls_v3.CertificateValidationContext{
				TrustedCa: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: []byte("-----BEGIN CERTIFICATE-----\nQlVORExF\n-----END CERTIFICATE-----\n"),
					},
				},
			},
		},
	}

	fedBundle = bundleutil.BundleFromRootCA("spiffe://otherdomain.test", &x509.Certificate{
		Raw: []byte("FEDBUNDLE"),
	})
	fedValidationContext = &tls_v3.Secret{
		Name: "spiffe://otherdomain.test",
		Type: &tls_v3.Secret_ValidationContext{
			ValidationContext: &tls_v3.CertificateValidationContext{
				TrustedCa: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: []byte("-----BEGIN CERTIFICATE-----\nRkVEQlVORExF\n-----END CERTIFICATE-----\n"),
					},
				},
			},
		},
	}

	workloadKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgN2PdPEglb3JjF1Fg
cqyEiRJHqtqzSUBnIeWCixn4hH2hRANCAARW+TsDRr0b0wJqg2kY5JvjX7UfAV3m
MC2hK9d8Z5ENZc9lFW48vObdcHcHdHvAaA8z2GM02pDkTt5pgUvRHlsf
-----END PRIVATE KEY-----
`)
	workloadKey, _ = pemutil.ParseECPrivateKey(workloadKeyPEM)

	workloadCert1           = &x509.Certificate{Raw: []byte("WORKLOAD1")}
	workloadTLSCertificate1 = &tls_v3.Secret{
		Name: "spiffe://domain.test/workload",
		Type: &tls_v3.Secret_TlsCertificate{
			TlsCertificate: &tls_v3.TlsCertificate{
				CertificateChain: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: []byte("-----BEGIN CERTIFICATE-----\nV09SS0xPQUQx\n-----END CERTIFICATE-----\n"),
					},
				},
				PrivateKey: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: workloadKeyPEM,
					},
				},
			},
		},
	}

	workloadCert2           = &x509.Certificate{Raw: []byte("WORKLOAD2")}
	workloadTLSCertificate2 = &tls_v3.Secret{
		Name: "spiffe://domain.test/workload",
		Type: &tls_v3.Secret_TlsCertificate{
			TlsCertificate: &tls_v3.TlsCertificate{
				CertificateChain: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: []byte("-----BEGIN CERTIFICATE-----\nV09SS0xPQUQy\n-----END CERTIFICATE-----\n"),
					},
				},
				PrivateKey: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: workloadKeyPEM,
					},
				},
			},
		},
	}

	workloadTLSCertificate3 = &tls_v3.Secret{
		Name: "default",
		Type: &tls_v3.Secret_TlsCertificate{
			TlsCertificate: &tls_v3.TlsCertificate{
				CertificateChain: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: []byte("-----BEGIN CERTIFICATE-----\nV09SS0xPQUQx\n-----END CERTIFICATE-----\n"),
					},
				},
				PrivateKey: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: workloadKeyPEM,
					},
				},
			},
		},
	}

	workloadSelectors = cache.Selectors{{Type: "TYPE", Value: "VALUE"}}
)

func TestHandler(t *testing.T) {
	spiretest.Run(t, new(HandlerSuite))
}

type HandlerSuite struct {
	spiretest.Suite
	manager  *FakeManager
	server   *grpc.Server
	handler  secret_v3.SecretDiscoveryServiceClient
	received chan struct{}
}

func (s *HandlerSuite) SetupTest() {
	s.manager = NewFakeManager(s.T())
	handler := New(Config{
		Attestor:          FakeAttestor(workloadSelectors),
		Manager:           s.manager,
		DefaultSVIDName:   "default",
		DefaultBundleName: "ROOTCA",
	})

	s.received = make(chan struct{})
	handler.hooks.received = s.received

	listener, err := net.Listen("tcp", "localhost:0")
	s.Require().NoError(err)

	conn, err := grpc.Dial(listener.Addr().String(), grpc.WithInsecure())
	s.Require().NoError(err)
	s.handler = secret_v3.NewSecretDiscoveryServiceClient(conn)

	log, _ := test.NewNullLogger()
	unaryInterceptor, streamInterceptor := middleware.Interceptors(middleware.WithLogger(log))
	server := grpc.NewServer(grpc.Creds(FakeCreds{}),
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
	)
	secret_v3.RegisterSecretDiscoveryServiceServer(server, handler)
	go func() { _ = server.Serve(listener) }()
	s.server = server

	s.setWorkloadUpdate(workloadCert1)
}

func (s *HandlerSuite) TearDownTest() {
	s.server.Stop()
}

func (s *HandlerSuite) TestStreamSecretsStreamAllSecrets() {
	stream, err := s.handler.StreamSecrets(context.Background())
	s.Require().NoError(err)
	defer func() {
		s.Require().NoError(stream.CloseSend())
	}()

	s.sendAndWait(stream, &discovery_v3.DiscoveryRequest{})

	resp, err := stream.Recv()
	s.Require().NoError(err)
	s.requireSecrets(resp, tdValidationContext, fedValidationContext, workloadTLSCertificate1)
}

func (s *HandlerSuite) TestStreamSecretsStreamTrustDomainBundleOnly() {
	stream, err := s.handler.StreamSecrets(context.Background())
	s.Require().NoError(err)
	defer func() {
		s.Require().NoError(stream.CloseSend())
	}()

	s.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"spiffe://domain.test"},
	})
	resp, err := stream.Recv()
	s.Require().NoError(err)
	s.requireSecrets(resp, tdValidationContext)
}

func (s *HandlerSuite) TestStreamSecretsStreamDefaultTrustDomainBundleOnly() {
	stream, err := s.handler.StreamSecrets(context.Background())
	s.Require().NoError(err)
	defer func() {
		s.Require().NoError(stream.CloseSend())
	}()

	s.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"ROOTCA"},
	})
	resp, err := stream.Recv()
	s.Require().NoError(err)
	s.requireSecrets(resp, tdValidationContext2)
}

func (s *HandlerSuite) TestStreamSecretsStreamFederatedTrustDomainBundleOnly() {
	stream, err := s.handler.StreamSecrets(context.Background())
	s.Require().NoError(err)
	defer func() {
		s.Require().NoError(stream.CloseSend())
	}()

	s.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"spiffe://otherdomain.test"},
	})
	resp, err := stream.Recv()
	s.Require().NoError(err)
	s.requireSecrets(resp, fedValidationContext)
}

func (s *HandlerSuite) TestStreamSecretsStreamTLSCertificateOnly() {
	stream, err := s.handler.StreamSecrets(context.Background())
	s.Require().NoError(err)
	defer func() {
		s.Require().NoError(stream.CloseSend())
	}()

	s.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"spiffe://domain.test/workload"},
	})
	resp, err := stream.Recv()
	s.Require().NoError(err)
	s.requireSecrets(resp, workloadTLSCertificate1)
}

func (s *HandlerSuite) TestStreamSecretsStreamDefaultTLSCertificateOnly() {
	stream, err := s.handler.StreamSecrets(context.Background())
	s.Require().NoError(err)
	defer func() {
		s.Require().NoError(stream.CloseSend())
	}()

	s.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"default"},
	})
	resp, err := stream.Recv()
	s.Require().NoError(err)
	s.requireSecrets(resp, workloadTLSCertificate3)
}

func (s *HandlerSuite) TestStreamSecretsUnknownResource() {
	stream, err := s.handler.StreamSecrets(context.Background())
	s.Require().NoError(err)
	defer func() {
		s.Require().NoError(stream.CloseSend())
	}()

	s.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"spiffe://domain.test/WHATEVER"},
	})
	_, err = stream.Recv()
	s.Require().Error(err)
}

func (s *HandlerSuite) TestStreamSecretsStreaming() {
	stream, err := s.handler.StreamSecrets(context.Background())
	s.Require().NoError(err)
	defer func() {
		s.Require().NoError(stream.CloseSend())
	}()

	s.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"spiffe://domain.test/workload"},
	})
	resp, err := stream.Recv()
	s.Require().NoError(err)
	s.Require().NotEmpty(resp.VersionInfo)
	s.Require().NotEmpty(resp.Nonce)
	s.requireSecrets(resp, workloadTLSCertificate1)

	s.setWorkloadUpdate(workloadCert2)

	resp, err = stream.Recv()
	s.Require().NoError(err)
	s.requireSecrets(resp, workloadTLSCertificate2)
}

func (s *HandlerSuite) TestStreamSecretsApplicationDoesNotSpin() {
	stream, err := s.handler.StreamSecrets(context.Background())
	s.Require().NoError(err)
	defer func() {
		s.Require().NoError(stream.CloseSend())
	}()

	// Subscribe to some updates
	s.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"spiffe://domain.test/workload"},
	})

	resp, err := stream.Recv()
	s.Require().NoError(err)
	s.requireSecrets(resp, workloadTLSCertificate1)

	// Reject the update
	s.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResponseNonce: resp.Nonce,
		VersionInfo:   "OHNO",
		ErrorDetail:   &status.Status{Message: "OHNO!"},
		ResourceNames: []string{"spiffe://domain.test/workload"},
	})

	s.setWorkloadUpdate(workloadCert2)

	resp, err = stream.Recv()
	s.Require().NoError(err)
	s.requireSecrets(resp, workloadTLSCertificate2)
}

func (s *HandlerSuite) TestStreamSecretsRequestReceivedBeforeWorkloadUpdate() {
	s.setWorkloadUpdate(nil)

	stream, err := s.handler.StreamSecrets(context.Background())
	s.Require().NoError(err)
	defer func() {
		s.Require().NoError(stream.CloseSend())
	}()

	s.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"spiffe://domain.test/workload"},
	})

	s.setWorkloadUpdate(workloadCert2)

	resp, err := stream.Recv()
	s.Require().NoError(err)
	s.requireSecrets(resp, workloadTLSCertificate2)
}

func (s *HandlerSuite) TestStreamSecretsSubChanged() {
	stream, err := s.handler.StreamSecrets(context.Background())
	s.Require().NoError(err)
	defer func() {
		s.Require().NoError(stream.CloseSend())
	}()

	s.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"spiffe://domain.test/workload"},
	})

	resp, err := stream.Recv()
	s.Require().NoError(err)
	s.requireSecrets(resp, workloadTLSCertificate1)

	// Ack the response
	s.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResponseNonce: resp.Nonce,
		VersionInfo:   resp.VersionInfo,
		ResourceNames: []string{"spiffe://domain.test/workload"},
	})

	// Send another request for different resources.
	s.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResponseNonce: resp.Nonce,
		VersionInfo:   resp.VersionInfo,
		ResourceNames: []string{"spiffe://domain.test"},
	})

	resp, err = stream.Recv()
	s.Require().NoError(err)
	s.requireSecrets(resp, tdValidationContext)
}

func (s *HandlerSuite) TestStreamSecretsBadNonce() {
	stream, err := s.handler.StreamSecrets(context.Background())
	s.Require().NoError(err)
	defer func() {
		s.Require().NoError(stream.CloseSend())
	}()

	// The first request should be good
	s.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"spiffe://domain.test/workload"},
	})
	resp, err := stream.Recv()
	s.Require().NoError(err)
	s.requireSecrets(resp, workloadTLSCertificate1)

	// Now update the workload SVID
	s.setWorkloadUpdate(workloadCert2)

	// The third request should be ignored because the nonce isn't set to
	// the value returned in the response.
	s.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResponseNonce: "FOO",
		VersionInfo:   resp.VersionInfo,
		ResourceNames: []string{"spiffe://domain.test"},
	})

	// The fourth request should be good since the nonce matches that sent with
	// the last response.
	s.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResponseNonce: resp.Nonce,
		VersionInfo:   resp.VersionInfo,
		ResourceNames: []string{"spiffe://domain.test/workload"},
	})
	resp, err = stream.Recv()
	s.Require().NoError(err)
	s.requireSecrets(resp, workloadTLSCertificate2)
}

func (s *HandlerSuite) TestFetchSecrets() {
	// Fetch all secrets
	resp, err := s.handler.FetchSecrets(context.Background(), &discovery_v3.DiscoveryRequest{TypeUrl: "TYPEURL"})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Empty(resp.VersionInfo)
	s.Require().Empty(resp.Nonce)
	s.Require().Equal("TYPEURL", resp.TypeUrl)
	s.requireSecrets(resp, tdValidationContext, fedValidationContext, workloadTLSCertificate1)

	// Fetch trust domain validation context only
	resp, err = s.handler.FetchSecrets(context.Background(), &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"spiffe://domain.test"},
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Empty(resp.VersionInfo)
	s.Require().Empty(resp.Nonce)
	s.requireSecrets(resp, tdValidationContext)

	// Fetch federated validation context only
	resp, err = s.handler.FetchSecrets(context.Background(), &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"spiffe://otherdomain.test"},
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Empty(resp.VersionInfo)
	s.Require().Empty(resp.Nonce)
	s.requireSecrets(resp, fedValidationContext)

	// Fetch tls certificate only
	resp, err = s.handler.FetchSecrets(context.Background(), &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"spiffe://domain.test/workload"},
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Empty(resp.VersionInfo)
	s.Require().Empty(resp.Nonce)
	s.requireSecrets(resp, workloadTLSCertificate1)

	// Fetch non-existent resource
	_, err = s.handler.FetchSecrets(context.Background(), &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"spiffe://domain.test/other"},
	})
	s.Require().Error(err)
}

func (s *HandlerSuite) setWorkloadUpdate(workloadCert *x509.Certificate) {
	var workloadUpdate *cache.WorkloadUpdate
	if workloadCert != nil {
		workloadUpdate = &cache.WorkloadUpdate{
			Identities: []cache.Identity{
				{
					Entry: &common.RegistrationEntry{
						SpiffeId: "spiffe://domain.test/workload",
					},
					SVID:       []*x509.Certificate{workloadCert},
					PrivateKey: workloadKey,
				},
			},
			Bundle: tdBundle,
			FederatedBundles: map[string]*bundleutil.Bundle{
				"spiffe://otherdomain.test": fedBundle,
			},
		}
	}
	s.manager.SetWorkloadUpdate(workloadUpdate)
}

func (s *HandlerSuite) sendAndWait(stream secret_v3.SecretDiscoveryService_StreamSecretsClient, req *discovery_v3.DiscoveryRequest) {
	s.Require().NoError(stream.Send(req))
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-s.received:
	case <-timer.C:
		s.Fail("timed out waiting for request to be received")
	}
}

func (s *HandlerSuite) requireSecrets(resp *discovery_v3.DiscoveryResponse, expectedSecrets ...*tls_v3.Secret) {
	var actualSecrets []*tls_v3.Secret
	for _, resource := range resp.Resources {
		secret := new(tls_v3.Secret)
		s.Require().NoError(resource.UnmarshalTo(secret)) //nolint: scopelint // pointer to resource isn't held
		actualSecrets = append(actualSecrets, secret)
	}

	s.RequireProtoListEqual(expectedSecrets, actualSecrets)
}

type FakeAttestor []*common.Selector

func (a FakeAttestor) Attest(ctx context.Context) ([]*common.Selector, error) {
	return ([]*common.Selector)(a), nil
}

type FakeManager struct {
	t *testing.T

	mu   sync.Mutex
	upd  *cache.WorkloadUpdate
	next int
	subs map[int]chan *cache.WorkloadUpdate
}

func NewFakeManager(t *testing.T) *FakeManager {
	return &FakeManager{
		t:    t,
		subs: make(map[int]chan *cache.WorkloadUpdate),
	}
}

func (m *FakeManager) SubscribeToCacheChanges(selectors cache.Selectors) cache.Subscriber {
	require.Equal(m.t, workloadSelectors, selectors)

	updch := make(chan *cache.WorkloadUpdate, 1)
	if m.upd != nil {
		updch <- m.upd
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	key := m.next
	m.next++
	m.subs[key] = updch
	return NewFakeSubscriber(updch, func() {
		delete(m.subs, key)
		close(updch)
	})
}

func (m *FakeManager) FetchWorkloadUpdate(selectors []*common.Selector) *cache.WorkloadUpdate {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.upd
}

func (m *FakeManager) SetWorkloadUpdate(upd *cache.WorkloadUpdate) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.upd = upd
	for _, sub := range m.subs {
		select {
		case sub <- upd:
		default:
			<-sub
			sub <- upd
		}
	}
}

type FakeSubscriber struct {
	updch <-chan *cache.WorkloadUpdate
	done  func()
}

func NewFakeSubscriber(updch <-chan *cache.WorkloadUpdate, done func()) *FakeSubscriber {
	return &FakeSubscriber{
		updch: updch,
		done:  done,
	}
}

func (s *FakeSubscriber) Updates() <-chan *cache.WorkloadUpdate {
	return s.updch
}

func (s *FakeSubscriber) Finish() {
	s.done()
}

type FakeCreds struct{}

func (c FakeCreds) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("unexpected")
}

func (c FakeCreds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, peertracker.AuthInfo{Watcher: FakeWatcher{}}, nil
}

func (c FakeCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "fixed",
		SecurityVersion:  "0.1",
		ServerName:       "sds-handler-test",
	}
}

func (c FakeCreds) Clone() credentials.TransportCredentials {
	return &c
}

func (c FakeCreds) OverrideServerName(_ string) error {
	return nil
}

type FakeWatcher struct{}

func (w FakeWatcher) Close() {}

func (w FakeWatcher) IsAlive() error { return nil }

func (w FakeWatcher) PID() int32 { return 123 }
