package registration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/server/datastore"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	rootCA1DER = pemBytes([]byte(`-----BEGIN CERTIFICATE-----
MIIBVzCB4gIJAJur7ujAmyDhMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNVBAMMCFRF
U1RST09UMB4XDTE4MTAxNTE4NDQxMVoXDTE5MTAxNTE4NDQxMVowEzERMA8GA1UE
AwwIVEVTVFJPT1QwfDANBgkqhkiG9w0BAQEFAANrADBoAmEAoYPq4DlrjDhanDM4
gDbEefDYi4IOmwUkQPAiJgQ2+CRm/pb/qc2zuj5FQZps1jxt3VtoDJnwfJuX6B4M
Zq0dHJF0ykfVonfxJbQsynge7yYA1avCLjlOv72Sk9/U8UQhAgMBAAEwDQYJKoZI
hvcNAQELBQADYQAXWlJO3EoYW3Uss0QjlqJJCC2M21HkF1AkWP6mUDgQ0PtbH2Vu
P58nzUo3Kzc3mfg3hocdt7vCDm75zdhjoDTLrT9IgU2XbDcbZF+yg51HZstonDiM
3JzUe9WQUljuQlM=
-----END CERTIFICATE-----
`))
	rootCA2DER = pemBytes([]byte(`-----BEGIN CERTIFICATE-----
MIIBWTCB5AIJAOIaaEWcPCB2MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCVRF
U1RST09UMjAeFw0xODEwMTUxODQ0MjdaFw0xOTEwMTUxODQ0MjdaMBQxEjAQBgNV
BAMMCVRFU1RST09UMjB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQCmsAlaUc8YCFs5
hl44gZ3CJvpR0Yc4DAQkgSfed06iN0rmBuQzeCl3hiJ9ogqw4va2ciVQ8hTPeMw6
047YCMKOkmhDa4dFgGzk9GlvUQF5qft1MTWYlCI6/jEfx4Zsd4ECAwEAATANBgkq
hkiG9w0BAQsFAANhADQochC62F37uubcBDR70qhJlC7Bsz/KgxtduQR4pSOj4uZh
zFHHu+k8dS32+KooMqtUp71bhMgtlvYIRay4OMD6VurfP70caOHkCVFPxibAW9o9
NbyKVndd7aGvTed1PQ==
-----END CERTIFICATE-----
`))
	udsAuth = peertracker.AuthInfo{}
)

func TestHandler(t *testing.T) {
	suite.Run(t, new(HandlerSuite))
}

type HandlerSuite struct {
	suite.Suite

	peer   *peer.Peer
	server *grpc.Server

	ds       *fakedatastore.DataStore
	serverCA *fakeserverca.CA
	handler  registration.RegistrationClient
}

func (s *HandlerSuite) SetupTest() {
	log, _ := test.NewNullLogger()

	s.ds = fakedatastore.New()
	s.serverCA = fakeserverca.New(s.T(), "example.org", nil)

	catalog := fakeservercatalog.New()
	catalog.SetDataStore(s.ds)

	handler := &Handler{
		Log:         log,
		Metrics:     telemetry.Blackhole{},
		TrustDomain: url.URL{Scheme: "spiffe", Host: "example.org"},
		Catalog:     catalog,
		ServerCA:    s.serverCA,
	}

	// we need to test a streaming API. without doing the same codegen we
	// did with plugins, implementing the server or client side interfaces
	// is a pain. start up a localhost server and test over that.
	s.server = grpc.NewServer()
	registration.RegisterRegistrationServer(s.server, handler)

	// start up a server over localhost
	listener, err := net.Listen("tcp", "localhost:0")
	s.Require().NoError(err)

	conn, err := grpc.Dial(listener.Addr().String(), grpc.WithInsecure())
	s.Require().NoError(err)

	go s.server.Serve(listener)
	s.handler = registration.NewRegistrationClient(conn)
}

func (s *HandlerSuite) TearDownTest() {
	s.server.Stop()
}

func (s *HandlerSuite) TestCreateFederatedBundle() {
	testCases := []struct {
		TrustDomainId string
		CaCerts       []byte
		Err           string
	}{
		{TrustDomainId: "spiffe://example.org", CaCerts: nil, Err: "federated bundle id cannot match server trust domain"},
		{TrustDomainId: "spiffe://otherdomain.org/spire/agent", CaCerts: nil, Err: `"spiffe://otherdomain.org/spire/agent" is not a valid trust domain SPIFFE ID: path is not empty`},
		{TrustDomainId: "spiffe://otherdomain.org", CaCerts: rootCA1DER, Err: ""},
		{TrustDomainId: "spiffe://otherdomain.org", CaCerts: rootCA1DER, Err: "bundle already exists"},
	}

	for _, testCase := range testCases {
		response, err := s.handler.CreateFederatedBundle(context.Background(), &registration.FederatedBundle{
			Bundle: bundleutil.BundleProtoFromRootCADER(testCase.TrustDomainId, testCase.CaCerts),
		})

		if testCase.Err != "" {
			s.requireErrorContains(err, testCase.Err)
			continue
		}
		s.Require().NoError(err)
		s.Require().Equal(&common.Empty{}, response)

		// assert that the bundle was created in the datastore
		resp, err := s.ds.FetchBundle(context.Background(), &datastore.FetchBundleRequest{
			TrustDomainId: testCase.TrustDomainId,
		})
		s.Require().NoError(err)
		s.Require().Equal(resp.Bundle.TrustDomainId, testCase.TrustDomainId)
		s.Require().Len(resp.Bundle.RootCas, 1)
		s.Require().Equal(resp.Bundle.RootCas[0].DerBytes, testCase.CaCerts)
	}
}

func (s *HandlerSuite) TestFetchFederatedBundle() {
	// Create three bundles
	s.createBundle(&common.Bundle{
		TrustDomainId: "spiffe://example.org",
		RootCas: []*common.Certificate{
			{DerBytes: []byte("EXAMPLE")},
		},
	})
	s.createBundle(&common.Bundle{
		TrustDomainId: "spiffe://otherdomain.org",
		RootCas: []*common.Certificate{
			{DerBytes: []byte("OTHERDOMAIN")},
		},
	})

	testCases := []struct {
		TrustDomainId string
		CaCerts       string
		Err           string
	}{
		{TrustDomainId: "spiffe://example.org", CaCerts: "", Err: "federated bundle id cannot match server trust domain"},
		{TrustDomainId: "spiffe://otherdomain.org/spire/agent", CaCerts: "", Err: `"spiffe://otherdomain.org/spire/agent" is not a valid trust domain SPIFFE ID: path is not empty`},
		{TrustDomainId: "spiffe://otherdomain.org", CaCerts: "OTHERDOMAIN", Err: ""},
		{TrustDomainId: "spiffe://yetotherdomain.org", CaCerts: "", Err: "bundle not found"},
	}

	for _, testCase := range testCases {
		response, err := s.handler.FetchFederatedBundle(context.Background(), &registration.FederatedBundleID{
			Id: testCase.TrustDomainId,
		})

		if testCase.Err != "" {
			s.requireErrorContains(err, testCase.Err)
			continue
		}
		s.Require().NoError(err)
		s.Require().NotNil(response)
		s.Require().Equal(bundleutil.BundleProtoFromRootCADER(testCase.TrustDomainId, []byte(testCase.CaCerts)), response.Bundle)
	}
}

func (s *HandlerSuite) TestListFederatedBundles() {
	s.createBundle(&common.Bundle{
		TrustDomainId: "spiffe://example.org",
		RootCas: []*common.Certificate{
			{DerBytes: []byte("EXAMPLE")},
		},
	})
	s.createBundle(&common.Bundle{
		TrustDomainId: "spiffe://example2.org",
		RootCas: []*common.Certificate{
			{DerBytes: []byte("EXAMPLE2")},
		},
	})

	// Assert that the listing does not contain the bundle for the server
	// trust domain
	stream, err := s.handler.ListFederatedBundles(context.Background(), &common.Empty{})
	s.Require().NoError(err)

	bundle, err := stream.Recv()
	s.Require().NoError(err)
	s.Require().Equal(&registration.FederatedBundle{
		Bundle: &common.Bundle{
			TrustDomainId: "spiffe://example2.org",
			RootCas: []*common.Certificate{
				{DerBytes: []byte("EXAMPLE2")},
			},
		},
	}, bundle)

	_, err = stream.Recv()
	s.Require().EqualError(err, "EOF")
}

func (s *HandlerSuite) TestUpdateFederatedBundle() {
	// create a bundle to be updated
	s.createBundle(&common.Bundle{
		TrustDomainId: "spiffe://otherdomain.org",
		RootCas: []*common.Certificate{
			{DerBytes: []byte("UPDATEME")},
		},
	})

	testCases := []struct {
		TrustDomainId string
		CaCerts       []byte
		Err           string
	}{
		{TrustDomainId: "spiffe://example.org", CaCerts: nil, Err: "federated bundle id cannot match server trust domain"},
		{TrustDomainId: "spiffe://otherdomain.org/spire/agent", CaCerts: nil, Err: `"spiffe://otherdomain.org/spire/agent" is not a valid trust domain SPIFFE ID: path is not empty`},
		{TrustDomainId: "spiffe://unknowndomain.org", CaCerts: rootCA1DER, Err: "no such bundle"},
		{TrustDomainId: "spiffe://otherdomain.org", CaCerts: rootCA1DER, Err: ""},
		{TrustDomainId: "spiffe://otherdomain.org", CaCerts: rootCA2DER, Err: ""},
	}

	for _, testCase := range testCases {
		s.T().Logf("case=%+v", testCase)
		response, err := s.handler.UpdateFederatedBundle(context.Background(), &registration.FederatedBundle{
			Bundle: bundleutil.BundleProtoFromRootCADER(testCase.TrustDomainId, testCase.CaCerts),
		})

		if testCase.Err != "" {
			s.requireErrorContains(err, testCase.Err)
			continue
		}
		s.Require().NoError(err)
		s.Require().Equal(&common.Empty{}, response)

		// assert that the bundle was created in the datastore
		resp, err := s.ds.FetchBundle(context.Background(), &datastore.FetchBundleRequest{
			TrustDomainId: testCase.TrustDomainId,
		})
		s.Require().NoError(err)
		s.Require().Equal(resp.Bundle.TrustDomainId, testCase.TrustDomainId)
		s.Require().Len(resp.Bundle.RootCas, 1)
		s.Require().Equal(resp.Bundle.RootCas[0].DerBytes, testCase.CaCerts)
	}
}

func (s *HandlerSuite) TestDeleteFederatedBundle() {
	testCases := []struct {
		TrustDomainId string
		Err           string
	}{
		{TrustDomainId: "spiffe://example.org", Err: "federated bundle id cannot match server trust domain"},
		{TrustDomainId: "spiffe://otherdomain.org/spire/agent", Err: `"spiffe://otherdomain.org/spire/agent" is not a valid trust domain SPIFFE ID: path is not empty`},
		{TrustDomainId: "spiffe://otherdomain.org", Err: ""},
		{TrustDomainId: "spiffe://otherdomain.org", Err: "no such bundle"},
	}

	s.createBundle(&common.Bundle{
		TrustDomainId: "spiffe://otherdomain.org",
		RootCas: []*common.Certificate{
			{DerBytes: []byte("BLAH")},
		},
	})

	for _, testCase := range testCases {
		response, err := s.handler.DeleteFederatedBundle(context.Background(), &registration.DeleteFederatedBundleRequest{
			Id: testCase.TrustDomainId,
		})

		if testCase.Err != "" {
			s.requireErrorContains(err, testCase.Err)
			continue
		}
		s.Require().NoError(err)
		s.Require().Equal(&common.Empty{}, response)

		// assert that the bundle was deleted
		resp, err := s.ds.FetchBundle(context.Background(), &datastore.FetchBundleRequest{
			TrustDomainId: testCase.TrustDomainId,
		})
		s.Require().NoError(err)
		s.Require().NotNil(resp)
		s.Require().Nil(resp.Bundle)
	}
}

func (s *HandlerSuite) TestCreateEntry() {
	testCases := []struct {
		Name  string
		Entry *common.RegistrationEntry
		Err   string
	}{
		{
			Name:  "Parent ID is malformed",
			Entry: &common.RegistrationEntry{ParentId: "FOO"},
			Err:   `"FOO" is not a valid trust domain member SPIFFE ID`,
		},
		{
			Name:  "SPIFFE ID is malformed",
			Entry: &common.RegistrationEntry{ParentId: "spiffe://example.org/parent", SpiffeId: "FOO"},
			Err:   `"FOO" is not a valid workload SPIFFE ID`,
		},
		{
			Name: "Bad DNS",
			Entry: &common.RegistrationEntry{
				ParentId:  "spiffe://example.org/parent",
				SpiffeId:  "spiffe://example.org/child",
				Selectors: []*common.Selector{{Type: "B", Value: "b"}},
				DnsNames:  []string{" "},
			},
			Err: "empty or only whitespace",
		},
		{
			Name: "Success",
			Entry: &common.RegistrationEntry{
				ParentId:  "spiffe://example.org/parent",
				SpiffeId:  "spiffe://example.org/child",
				Selectors: []*common.Selector{{Type: "B", Value: "b"}},
				DnsNames:  []string{"abcd.ef"},
			},
		},
		{
			Name: "AlreadyExists",
			Entry: &common.RegistrationEntry{
				ParentId:  "spiffe://example.org/parent",
				SpiffeId:  "spiffe://example.org/child",
				Selectors: []*common.Selector{{Type: "B", Value: "b"}},
			},
			Err: status.Error(codes.AlreadyExists, "entry already exists").Error(),
		},
	}

	for _, testCase := range testCases {
		s.T().Run(testCase.Name, func(t *testing.T) {
			resp, err := s.handler.CreateEntry(context.Background(), testCase.Entry)
			if testCase.Err != "" {
				requireErrorContains(t, err, testCase.Err)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, resp.Id)

			entry, err := s.ds.FetchRegistrationEntry(context.Background(), &datastore.FetchRegistrationEntryRequest{
				EntryId: resp.Id,
			})
			require.NoError(t, err)
			require.NotNil(t, entry)
			// set ID (unknown before fetch) to do comparison
			testCase.Entry.EntryId = entry.Entry.EntryId
			t.Logf("actual=%+v expected=%+v", entry.Entry, testCase.Entry)
			require.True(t, proto.Equal(entry.Entry, testCase.Entry))
		})
	}
}

func (s *HandlerSuite) TestUpdateEntry() {
	entry := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  "spiffe://example.org/foo",
		SpiffeId:  "spiffe://example.org/bar",
		Selectors: []*common.Selector{{Type: "A", Value: "a"}},
	})

	testCases := []struct {
		Name  string
		Entry *common.RegistrationEntry
		Err   string
	}{
		{
			Name: "Missing entry",
			Err:  "missing entry to update",
		},
		{
			Name:  "Parent ID is malformed",
			Entry: &common.RegistrationEntry{EntryId: "X", ParentId: "FOO"},
			Err:   `"FOO" is not a valid trust domain member SPIFFE ID`,
		},
		{
			Name:  "SPIFFE ID is malformed",
			Entry: &common.RegistrationEntry{EntryId: "X", ParentId: "spiffe://example.org/parent", SpiffeId: "FOO"},
			Err:   `"FOO" is not a valid workload SPIFFE ID`,
		},
		{
			Name:  "Registration entry does not exist",
			Entry: &common.RegistrationEntry{EntryId: "X", ParentId: "spiffe://example.org/parent", SpiffeId: "spiffe://example.org/child"},
			Err:   "no such registration entry",
		},
		{
			Name: "Bad DNS",
			Entry: &common.RegistrationEntry{
				EntryId:   entry.EntryId,
				ParentId:  "spiffe://example.org/parent",
				SpiffeId:  "spiffe://example.org/child",
				Selectors: []*common.Selector{{Type: "B", Value: "b"}},
				DnsNames:  []string{" "},
			},
			Err: "empty or only whitespace",
		},
		{
			Name: "Success",
			Entry: &common.RegistrationEntry{
				EntryId:   entry.EntryId,
				ParentId:  "spiffe://example.org/parent",
				SpiffeId:  "spiffe://example.org/child",
				Selectors: []*common.Selector{{Type: "B", Value: "b"}},
				DnsNames:  []string{"wxyz.2-a"},
			},
		},
	}

	for _, testCase := range testCases {
		s.T().Run(testCase.Name, func(t *testing.T) {
			resp, err := s.handler.UpdateEntry(context.Background(), &registration.UpdateEntryRequest{
				Entry: testCase.Entry,
			})

			if testCase.Err != "" {
				requireErrorContains(t, err, testCase.Err)
				return
			}
			require.NoError(t, err)
			t.Logf("actual=%+v expected=%+v", resp, testCase.Entry)
			require.True(t, proto.Equal(resp, testCase.Entry))
		})
	}
}

func (s *HandlerSuite) TestDeleteEntry() {
	entry := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  "spiffe://example.org/foo",
		SpiffeId:  "spiffe://example.org/bar",
		Selectors: []*common.Selector{{Type: "A", Value: "a"}},
	})

	testCases := []struct {
		Name    string
		EntryId string
		Err     string
	}{
		{
			Name:    "Success",
			EntryId: entry.EntryId,
		},
		{
			Name: "Registration entry does not exist",
			Err:  "no such registration entry",
		},
	}

	for _, testCase := range testCases {
		s.T().Run(testCase.Name, func(t *testing.T) {
			resp, err := s.handler.DeleteEntry(context.Background(), &registration.RegistrationEntryID{
				Id: testCase.EntryId,
			})

			if testCase.Err != "" {
				requireErrorContains(t, err, testCase.Err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, resp.EntryId, testCase.EntryId)
		})
	}
}

func (s *HandlerSuite) TestFetchEntry() {
	entry := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  "spiffe://example.org/foo",
		SpiffeId:  "spiffe://example.org/bar",
		Selectors: []*common.Selector{{Type: "A", Value: "a"}},
	})

	testCases := []struct {
		Name    string
		EntryId string
		Err     string
	}{
		{
			Name:    "Success",
			EntryId: entry.EntryId,
		},
		{
			Name: "Registration entry does not exist",
			Err:  "no such registration entry",
		},
	}

	for _, testCase := range testCases {
		s.T().Run(testCase.Name, func(t *testing.T) {
			resp, err := s.handler.FetchEntry(context.Background(), &registration.RegistrationEntryID{
				Id: testCase.EntryId,
			})

			if testCase.Err != "" {
				requireErrorContains(t, err, testCase.Err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, resp.EntryId, testCase.EntryId)
		})
	}
}

func (s *HandlerSuite) TestFetchEntries() {
	// No entries
	resp, err := s.handler.FetchEntries(context.Background(), &common.Empty{})
	s.Require().NoError(err)
	s.Require().Len(resp.Entries, 0)

	// One entry
	entry1 := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  "spiffe://example.org/foo",
		SpiffeId:  "spiffe://example.org/bar",
		Selectors: []*common.Selector{{Type: "A", Value: "a"}},
	})
	resp, err = s.handler.FetchEntries(context.Background(), &common.Empty{})
	s.Require().NoError(err)
	s.Require().Len(resp.Entries, 1)
	s.Require().True(proto.Equal(entry1, resp.Entries[0]))

	// More than one entry
	entry2 := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  "spiffe://example.org/foo",
		SpiffeId:  "spiffe://example.org/baz",
		Selectors: []*common.Selector{{Type: "A", Value: "a"}},
	})
	resp, err = s.handler.FetchEntries(context.Background(), &common.Empty{})
	s.Require().NoError(err)
	s.Require().Len(resp.Entries, 2)
	s.Require().True(proto.Equal(entry1, resp.Entries[0]))
	s.Require().True(proto.Equal(entry2, resp.Entries[1]))
}

func (s *HandlerSuite) TestListByParentId() {
	entry1 := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  "spiffe://example.org/foo",
		SpiffeId:  "spiffe://example.org/bar",
		Selectors: []*common.Selector{{Type: "A", Value: "a"}},
	})
	entry2 := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  "spiffe://example.org/foo",
		SpiffeId:  "spiffe://example.org/baz",
		Selectors: []*common.Selector{{Type: "A", Value: "a"}},
	})
	entry3 := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  "spiffe://example.org/buz",
		SpiffeId:  "spiffe://example.org/fuz",
		Selectors: []*common.Selector{{Type: "A", Value: "a"}},
	})

	// Malformed ID
	resp, err := s.handler.ListByParentID(context.Background(), &registration.ParentID{
		Id: "whatever",
	})
	s.requireErrorContains(err, `"whatever" is not a valid SPIFFE ID`)
	s.Require().Nil(resp)

	// No entries
	resp, err = s.handler.ListByParentID(context.Background(), &registration.ParentID{
		Id: "spiffe://example.org/whatever",
	})
	s.Require().NoError(err)
	s.Require().Len(resp.Entries, 0)

	// One entry
	resp, err = s.handler.ListByParentID(context.Background(), &registration.ParentID{
		Id: "spiffe://example.org/buz",
	})
	s.Require().NoError(err)
	s.Require().Len(resp.Entries, 1)
	s.Require().True(proto.Equal(entry3, resp.Entries[0]))

	// More than one entry
	resp, err = s.handler.ListByParentID(context.Background(), &registration.ParentID{
		Id: "spiffe://example.org/foo",
	})
	s.Require().NoError(err)
	s.Require().Len(resp.Entries, 2)
	s.Require().True(proto.Equal(entry1, resp.Entries[0]))
	s.Require().True(proto.Equal(entry2, resp.Entries[1]))
}

func (s *HandlerSuite) TestListBySelector() {
	entry1 := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  "spiffe://example.org/foo",
		SpiffeId:  "spiffe://example.org/bar",
		Selectors: []*common.Selector{{Type: "A", Value: "a"}},
	})
	entry2 := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  "spiffe://example.org/foo",
		SpiffeId:  "spiffe://example.org/baz",
		Selectors: []*common.Selector{{Type: "A", Value: "a"}},
	})
	entry3 := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  "spiffe://example.org/buz",
		SpiffeId:  "spiffe://example.org/fuz",
		Selectors: []*common.Selector{{Type: "B", Value: "b"}},
	})

	// No entries
	resp, err := s.handler.ListBySelector(context.Background(), &common.Selector{Type: "C", Value: "c"})
	s.Require().NoError(err)
	s.Require().Len(resp.Entries, 0)

	// One entry
	resp, err = s.handler.ListBySelector(context.Background(), &common.Selector{Type: "B", Value: "b"})
	s.Require().NoError(err)
	s.Require().Len(resp.Entries, 1)
	s.Require().True(proto.Equal(entry3, resp.Entries[0]))

	// More than one entry
	resp, err = s.handler.ListBySelector(context.Background(), &common.Selector{Type: "A", Value: "a"})
	s.Require().NoError(err)
	s.Require().Len(resp.Entries, 2)
	s.Require().True(proto.Equal(entry1, resp.Entries[0]))
	s.Require().True(proto.Equal(entry2, resp.Entries[1]))
}

func (s *HandlerSuite) TestListBySelectors() {
	entry1 := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  "spiffe://example.org/foo",
		SpiffeId:  "spiffe://example.org/bar",
		Selectors: []*common.Selector{{Type: "A", Value: "a"}, {Type: "Z", Value: "z"}},
	})
	entry2 := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  "spiffe://example.org/foo",
		SpiffeId:  "spiffe://example.org/baz",
		Selectors: []*common.Selector{{Type: "A", Value: "a"}, {Type: "Z", Value: "z"}},
	})
	entry3 := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  "spiffe://example.org/buz",
		SpiffeId:  "spiffe://example.org/fuz",
		Selectors: []*common.Selector{{Type: "B", Value: "b"}, {Type: "Z", Value: "z"}},
	})

	// No entries
	resp, err := s.handler.ListBySelectors(context.Background(), &common.Selectors{
		Entries: []*common.Selector{
			{Type: "C", Value: "c"},
			{Type: "Z", Value: "z"},
		},
	})
	s.Require().NoError(err)
	s.Require().Len(resp.Entries, 0)

	// One entry
	resp, err = s.handler.ListBySelectors(context.Background(), &common.Selectors{
		Entries: []*common.Selector{
			{Type: "B", Value: "b"},
			{Type: "Z", Value: "z"},
		},
	})
	s.Require().NoError(err)
	s.Require().Len(resp.Entries, 1)
	s.Require().True(proto.Equal(entry3, resp.Entries[0]))

	// More than one entry
	resp, err = s.handler.ListBySelectors(context.Background(), &common.Selectors{
		Entries: []*common.Selector{
			{Type: "A", Value: "a"},
			{Type: "Z", Value: "z"},
		},
	})
	s.Require().NoError(err)
	s.Require().Len(resp.Entries, 2)
	s.Require().True(proto.Equal(entry1, resp.Entries[0]))
	s.Require().True(proto.Equal(entry2, resp.Entries[1]))
}

func (s *HandlerSuite) TestListBySpiffeID() {
	entry1 := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  "spiffe://example.org/parent",
		SpiffeId:  "spiffe://example.org/foo",
		Selectors: []*common.Selector{{Type: "A", Value: "a"}},
	})
	entry2 := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  "spiffe://example.org/parent",
		SpiffeId:  "spiffe://example.org/foo",
		Selectors: []*common.Selector{{Type: "B", Value: "b"}},
	})
	entry3 := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  "spiffe://example.org/parent",
		SpiffeId:  "spiffe://example.org/bar",
		Selectors: []*common.Selector{{Type: "A", Value: "a"}},
	})

	// Malformed ID
	resp, err := s.handler.ListBySpiffeID(context.Background(), &registration.SpiffeID{
		Id: "whatever",
	})
	s.requireErrorContains(err, `"whatever" is not a valid SPIFFE ID`)
	s.Require().Nil(resp)

	// No entries
	resp, err = s.handler.ListBySpiffeID(context.Background(), &registration.SpiffeID{
		Id: "spiffe://example.org/whatever",
	})
	s.Require().NoError(err)
	s.Require().Len(resp.Entries, 0)

	// One entry
	resp, err = s.handler.ListBySpiffeID(context.Background(), &registration.SpiffeID{
		Id: "spiffe://example.org/bar",
	})
	s.Require().NoError(err)
	s.Require().Len(resp.Entries, 1)
	s.Require().True(proto.Equal(entry3, resp.Entries[0]))

	// More than one entry
	resp, err = s.handler.ListBySpiffeID(context.Background(), &registration.SpiffeID{
		Id: "spiffe://example.org/foo",
	})
	s.Require().NoError(err)
	s.Require().Len(resp.Entries, 2)
	s.Require().True(proto.Equal(entry1, resp.Entries[0]))
	s.Require().True(proto.Equal(entry2, resp.Entries[1]))
}

func (s *HandlerSuite) TestCreateJoinToken() {
	// No ttl
	resp, err := s.handler.CreateJoinToken(context.Background(), &registration.JoinToken{Token: "foo"})
	s.requireErrorContains(err, "ttl is required")
	s.Require().Nil(resp)

	// No token specified (one will be generated)
	resp, err = s.handler.CreateJoinToken(context.Background(), &registration.JoinToken{Ttl: 1})
	s.Require().NoError(err)
	s.Require().NotEmpty(resp.Token)
	s.Require().Equal(int32(1), resp.Ttl)

	// Token specified
	resp, err = s.handler.CreateJoinToken(context.Background(), &registration.JoinToken{Token: "foo", Ttl: 1})
	s.Require().NoError(err)
	s.Require().Equal(resp, &registration.JoinToken{Token: "foo", Ttl: 1})

	// Already exists
	resp, err = s.handler.CreateJoinToken(context.Background(), &registration.JoinToken{Token: "foo", Ttl: 1})
	s.requireErrorContains(err, "Failed to register token")
	s.Require().Nil(resp)
}

func (s *HandlerSuite) TestFetchBundle() {
	// No bundle
	resp, err := s.handler.FetchBundle(context.Background(), &common.Empty{})
	s.requireErrorContains(err, "bundle not found")
	s.Require().Nil(resp)

	// Success
	s.createBundle(&common.Bundle{
		TrustDomainId: "spiffe://example.org",
		RootCas: []*common.Certificate{
			{DerBytes: []byte("EXAMPLE")},
		},
	})
	resp, err = s.handler.FetchBundle(context.Background(), &common.Empty{})
	s.Require().NoError(err)
	s.Require().Equal(&registration.Bundle{
		Bundle: &common.Bundle{
			TrustDomainId: "spiffe://example.org",
			RootCas: []*common.Certificate{
				{DerBytes: []byte("EXAMPLE")},
			},
		},
	}, resp)
}

func (s *HandlerSuite) TestEvictAgent() {
	spiffeIDToRemove := "spiffe://example.org/spire/agent/join_token/token_a"
	evictRequest := &registration.EvictAgentRequest{SpiffeID: spiffeIDToRemove}
	ctx := context.Background()
	node := s.createAttestedNode(spiffeIDToRemove)
	evictResponse, err := s.handler.EvictAgent(ctx, evictRequest)
	s.Require().NoError(err)
	s.Equal(evictResponse.Node, node, "Evict did not remove spiffeID: %q", spiffeIDToRemove)
}

func (s *HandlerSuite) TestEvictAgentWithNonExistentId() {
	spiffeIDToAdd := "spiffe://example.org/spire/agent/join_token/token_a"
	spiffeIDToRemove := "spiffe://example.org/spire/agent/join_token/token_b"
	ctx := context.Background()
	s.createAttestedNode(spiffeIDToAdd)
	evictRequest := &registration.EvictAgentRequest{SpiffeID: spiffeIDToRemove}

	// Trying to remove a non existent spiffeID
	_, err := s.handler.EvictAgent(ctx, evictRequest)
	s.Error(err, "Evict should have failed")
}

func (s *HandlerSuite) TestListAgents() {
	// Creating attested nodes list
	ctx := context.Background()
	spiffeID1 := "spiffe://example.org/spire/agent/join_token/token_a"
	spiffeID2 := "spiffe://example.org/spire/agent/join_token/token_b"
	expectedNodeList := []*common.AttestedNode{
		{SpiffeId: spiffeID1},
		{SpiffeId: spiffeID2},
	}
	s.createAttestedNode(spiffeID1)
	s.createAttestedNode(spiffeID2)

	// Listing agents
	listResponse, err := s.handler.ListAgents(ctx, &registration.ListAgentsRequest{})
	s.Require().NoError(err)
	s.Len(listResponse.Nodes, 2)
	s.Equal(listResponse.Nodes, expectedNodeList)
}

func (s *HandlerSuite) TestListWithNoAgents() {
	// Creating attested nodes list
	ctx := context.Background()

	// Listing agents
	listResponse, err := s.handler.ListAgents(ctx, &registration.ListAgentsRequest{})
	s.Require().NoError(err)
	s.Len(listResponse.Nodes, 0)
}

func (s *HandlerSuite) TestMintX509SVID() {
	bundle := &common.Bundle{
		TrustDomainId: "spiffe://example.org",
		RootCas: []*common.Certificate{
			{DerBytes: []byte("EXAMPLE")},
		},
	}
	s.createBundle(bundle)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s.Require().NoError(err)

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	s.Require().NoError(err)

	badCSR := append([]byte{}, csr...)
	badCSR[len(badCSR)-1]++
	badCSR[len(badCSR)-2]++
	badCSR[len(badCSR)-3]++
	badCSR[len(badCSR)-4]++

	testCases := []struct {
		name string
		req  *registration.MintX509SVIDRequest
		err  error
	}{
		{
			name: "SPIFFE ID is missing",
			req: &registration.MintX509SVIDRequest{
				Csr: csr,
			},
			err: status.Error(codes.InvalidArgument, `request missing SPIFFE ID`),
		},
		{
			name: "SPIFFE ID is not for a workload in the trust domain",
			req: &registration.MintX509SVIDRequest{
				SpiffeId: "spiffe://example.org",
				Csr:      csr,
			},
			err: status.Error(codes.InvalidArgument, `"spiffe://example.org" is not a valid workload SPIFFE ID: path is empty`),
		},
		{
			name: "SPIFFE ID is not for the trust domain",
			req: &registration.MintX509SVIDRequest{
				SpiffeId: "spiffe://domain.test/workload",
				Csr:      csr,
			},
			err: status.Error(codes.InvalidArgument, `"spiffe://domain.test/workload" does not belong to trust domain "example.org"`),
		},
		{
			name: "CSR is missing",
			req: &registration.MintX509SVIDRequest{
				SpiffeId: "spiffe://example.org/workload",
			},
			err: status.Error(codes.InvalidArgument, `request missing CSR`),
		},
		{
			name: "CSR is malformed",
			req: &registration.MintX509SVIDRequest{
				SpiffeId: "spiffe://example.org/workload",
				Csr:      []byte{1},
			},
			err: status.Error(codes.InvalidArgument, `invalid CSR: asn1: syntax error: truncated tag or length`),
		},
		{
			name: "CSR signature is bad",
			req: &registration.MintX509SVIDRequest{
				SpiffeId: "spiffe://example.org/workload",
				Csr:      badCSR,
			},
			err: status.Error(codes.InvalidArgument, `invalid CSR: signature verify failed`),
		},
		{
			name: "bad DNS name",
			req: &registration.MintX509SVIDRequest{
				SpiffeId: "spiffe://example.org/workload",
				Csr:      csr,
				DnsNames: []string{"domain."},
			},
			err: status.Error(codes.InvalidArgument, `invalid DNS name: label is empty`),
		},
		{
			name: "success with default TTL and no DNS names",
			req: &registration.MintX509SVIDRequest{
				SpiffeId: "spiffe://example.org/workload",
				Csr:      csr,
			},
		},
		{
			name: "success with specific TTL and DNS names",
			req: &registration.MintX509SVIDRequest{
				SpiffeId: "spiffe://example.org/workload",
				Csr:      csr,
				Ttl:      1,
				DnsNames: []string{"foo.example.org", "bar.example.org"},
			},
		},
	}

	for _, testCase := range testCases {
		s.T().Run(testCase.name, func(t *testing.T) {
			req := testCase.req
			resp, err := s.handler.MintX509SVID(context.Background(), req)
			if testCase.err != nil {
				st := status.Convert(testCase.err)
				spiretest.RequireGRPCStatus(t, err, st.Code(), st.Message())
				return
			}
			require.NoError(t, err)
			require.Len(t, resp.RootCas, len(bundle.RootCas))
			for i, rootCA := range resp.RootCas {
				require.Equal(t, bundle.RootCas[i].DerBytes, rootCA)
			}
			require.NotEmpty(t, resp.SvidChain)

			svid, err := x509.ParseCertificate(resp.SvidChain[0])
			require.NoError(t, err)

			// assert the SPIFFE ID
			require.Len(t, svid.URIs, 1)
			require.Equal(t, req.SpiffeId, svid.URIs[0].String())

			// assert the certificate lifetime
			now := s.serverCA.Clock().Now().UTC().Truncate(time.Second)
			if req.Ttl == 0 {
				require.Equal(t, now.Add(s.serverCA.X509SVIDTTL()), svid.NotAfter)
			} else {
				require.Equal(t, now.Add(time.Duration(req.Ttl)*time.Second), svid.NotAfter)
			}

			// assert that the DNS names have been set correctly
			require.Equal(t, req.DnsNames, svid.DNSNames)

			// assert that the first DNS name is set as the common name
			if len(req.DnsNames) > 0 {
				require.Equal(t, req.DnsNames[0], svid.Subject.CommonName)
			}
		})
	}
}

func (s *HandlerSuite) TestMintJWTSVID() {
	testCases := []struct {
		name string
		req  *registration.MintJWTSVIDRequest
		err  error
	}{
		{
			name: "SPIFFE ID is missing",
			req: &registration.MintJWTSVIDRequest{
				Audience: []string{"AUDIENCE"},
			},
			err: status.Error(codes.InvalidArgument, `request missing SPIFFE ID`),
		},
		{
			name: "SPIFFE ID is not for a workload in the trust domain",
			req: &registration.MintJWTSVIDRequest{
				SpiffeId: "spiffe://example.org",
				Audience: []string{"AUDIENCE"},
			},
			err: status.Error(codes.InvalidArgument, `"spiffe://example.org" is not a valid workload SPIFFE ID: path is empty`),
		},
		{
			name: "SPIFFE ID is not for the trust domain",
			req: &registration.MintJWTSVIDRequest{
				SpiffeId: "spiffe://domain.test/workload",
				Audience: []string{"AUDIENCE"},
			},
			err: status.Error(codes.InvalidArgument, `"spiffe://domain.test/workload" does not belong to trust domain "example.org"`),
		},
		{
			name: "audience is missing",
			req: &registration.MintJWTSVIDRequest{
				SpiffeId: "spiffe://example.org/workload",
			},
			err: status.Error(codes.InvalidArgument, `request must specify at least one audience`),
		},
		{
			name: "success with default TTL",
			req: &registration.MintJWTSVIDRequest{
				SpiffeId: "spiffe://example.org/workload",
				Audience: []string{"AUDIENCE"},
			},
		},
		{
			name: "success with specified TTL and extra audience",
			req: &registration.MintJWTSVIDRequest{
				SpiffeId: "spiffe://example.org/workload",
				Audience: []string{"AUDIENCE1", "AUDIENCE2"},
				Ttl:      1,
			},
		},
	}

	for _, testCase := range testCases {
		s.T().Run(testCase.name, func(t *testing.T) {
			req := testCase.req
			resp, err := s.handler.MintJWTSVID(context.Background(), req)
			if testCase.err != nil {
				st := status.Convert(testCase.err)
				spiretest.RequireGRPCStatus(t, err, st.Code(), st.Message())
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, resp.Token)

			token, err := jwt.ParseSigned(resp.Token)
			require.NoError(t, err)

			var claims jwt.Claims
			err = token.UnsafeClaimsWithoutVerification(&claims)
			require.NoError(t, err)

			require.Equal(t, req.SpiffeId, claims.Subject)
			require.Equal(t, jwt.Audience(req.Audience), claims.Audience)
			require.NotNil(t, claims.Expiry)

			expiry := time.Unix(int64(*claims.Expiry), 0).UTC()
			now := s.serverCA.Clock().Now().UTC().Truncate(time.Second)
			if req.Ttl == 0 {
				require.Equal(t, now.Add(s.serverCA.JWTSVIDTTL()), expiry)
			} else {
				require.Equal(t, now.Add(time.Duration(req.Ttl)*time.Second), expiry)
			}
		})
	}

}

func (s *HandlerSuite) TestGetNodeSelectors() {
	// Setting node selectors
	ctx := context.Background()
	spiffeID := "spiffe://example.org/spire/agent/k8s_sat/demo-cluster/c54f273c-f9c2-4d08-9d6f-08879e418aef"
	selectors := []*common.Selector{
		{Type: "k8s_sat", Value: "agent_ns:spire"},
		{Type: "k8s_sat", Value: "agent_sa:spire-agent"},
		{Type: "k8s_sat", Value: "cluster:demo-cluster"},
	}
	expectedNodeSelectors := &registration.NodeSelectors{
		SpiffeId:  spiffeID,
		Selectors: selectors,
	}
	s.setNodeSelectors(spiffeID, selectors)

	// Getting node selectors
	req := &registration.GetNodeSelectorsRequest{SpiffeId: spiffeID}
	resp, err := s.handler.GetNodeSelectors(ctx, req)
	s.Require().NoError(err)
	s.Equal(resp.Selectors, expectedNodeSelectors)
}

func (s *HandlerSuite) createAttestedNode(spiffeID string) *common.AttestedNode {
	createResponse, err := s.ds.CreateAttestedNode(context.Background(), &datastore.CreateAttestedNodeRequest{
		Node: &common.AttestedNode{
			SpiffeId: spiffeID,
		},
	})
	s.Require().NoError(err, "Failed to create attested node")
	return createResponse.Node
}

func (s *HandlerSuite) TestAuthorizeCall() {
	catalog := fakeservercatalog.New()
	catalog.SetDataStore(s.ds)
	log, _ := test.NewNullLogger()
	handler := &Handler{Log: log, Catalog: catalog}

	makeTLSPeer := func(spiffeID string) *peer.Peer {
		cert := &x509.Certificate{}
		if spiffeID != "" {
			u, err := url.Parse(spiffeID)
			s.Require().NoError(err)
			cert.URIs = append(cert.URIs, u)
		}
		return &peer.Peer{
			AuthInfo: credentials.TLSInfo{
				State: tls.ConnectionState{
					VerifiedChains: [][]*x509.Certificate{{cert}},
				},
			},
		}
	}

	s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId: "spiffe://example.org/parent",
		SpiffeId: "spiffe://example.org/admin",
		Admin:    true,
	})

	testCases := []struct {
		Peer     *peer.Peer
		CallerID string
		Err      string
	}{
		{
			Err: "no peer information for caller",
		},
		{
			Peer: &peer.Peer{},
			Err:  "unsupported peer auth info type",
		},
		{
			Peer: &peer.Peer{
				AuthInfo: peertracker.AuthInfo{},
			},
		},
		{
			Peer: &peer.Peer{
				AuthInfo: credentials.TLSInfo{},
			},
			Err: "no verified client certificate",
		},
		{
			Peer: &peer.Peer{
				AuthInfo: credentials.TLSInfo{
					State: tls.ConnectionState{
						VerifiedChains: [][]*x509.Certificate{{}},
					},
				},
			},
			Err: "verified chain is empty",
		},
		{
			Peer: makeTLSPeer(""),
			Err:  "no SPIFFE ID in certificate",
		},
		{
			Peer: makeTLSPeer("whatever://example.org"),
			Err:  "not a valid SPIFFE ID",
		},
		{
			Peer: makeTLSPeer("spiffe://example.org/not-admin"),
			Err:  `SPIFFE ID "spiffe://example.org/not-admin" is not authorized`,
		},
		{
			Peer:     makeTLSPeer("spiffe://example.org/admin"),
			CallerID: "spiffe://example.org/admin",
		},
	}

	for _, testCase := range testCases {
		s.T().Logf("case=%+v", testCase)
		ctx := context.Background()
		if testCase.Peer != nil {
			ctx = peer.NewContext(ctx, testCase.Peer)
		}
		ctx, err := handler.AuthorizeCall(ctx, "SOMEMETHOD")
		if testCase.Err != "" {
			s.requireErrorContains(err, testCase.Err)
			s.requireGRPCStatusCode(err, codes.PermissionDenied)
			continue
		}
		s.Require().NoError(err)
		s.Require().Equal(testCase.CallerID, getCallerID(ctx), "Caller SPIFFE ID on context")
	}
}

func TestDNSValidation(t *testing.T) {
	tests := []struct {
		name string
		dns  string
		err  string
	}{
		{
			name: "empty dns",
			dns:  "",
			err:  "empty or only whitespace",
		},
		{
			name: "whitespace dns",
			dns:  " ",
			err:  "empty or only whitespace",
		},
		{
			name: "too long dns",
			dns: `BE3a7lf7WXVVf3ZyIJanGE7EhNxeAXEqCtSHXIxs3WRS5TXhmL1gzh2
KeW2wxmM5kVCi7KXYRha9iiULyrrzkL8mmaxdd05KoHwFuvSL7EUkWfhzzBQ65ZbK8VX
KpAxWdCD5cd2Vwzgz1ndMTt0aQUqfQiTvi0xXoe18ksShkOboNoEIWoaRoAwnSwbF01S
INk16I343I4FortWWCEV9nprutN3KQCZiIhHGkK4zQ6iyH7mTGc5bOfPIqE4aLynK`,
			err: "length exceeded",
		},
		{
			name: "dot only dns",
			dns:  ".",
			err:  "label is empty",
		},
		{
			name: "ending dot dns",
			dns:  "abcd.",
			err:  "label is empty",
		},
		{
			name: "too long label",
			dns:  "lFU37hAAULjx5LpB32MGe03GfrPqnQqLWBiWkkUYYJbIRBt7QlqahDbeshsd9JhP",
			err:  "label length exceeded: lFU37hAAULjx5LpB32MGe03GfrPqnQqLWBiWkkUYYJbIRBt7QlqahDbeshsd9JhP",
		},
		{
			name: "ending hyphen",
			dns:  "abc-",
			err:  "label does not match regex: abc-",
		},
		{
			name: "starting hyphen",
			dns:  "-abc",
			err:  "label does not match regex: -abc",
		},
		{
			name: "invalid character",
			dns:  "abc.df0f&",
			err:  "label does not match regex: df0f&",
		},
		{
			name: "consecutive hyphens",
			dns:  "abc.df--0f",
			err:  "",
		},
		{
			name: "series of hyphens",
			dns:  "abc.df--0------f",
			err:  "",
		},
		{
			name: "no hyphens",
			dns:  "abc.df0f.fa247d",
			err:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDNS(tt.dns)

			if tt.err == "" {
				assert.NoError(t, err)
			} else {
				assert.Contains(t, err.Error(), tt.err)
			}
		})
	}
}

func (s *HandlerSuite) createBundle(bundle *common.Bundle) {
	_, err := s.ds.CreateBundle(context.Background(), &datastore.CreateBundleRequest{
		Bundle: bundle,
	})
	s.Require().NoError(err)
}

func (s *HandlerSuite) createRegistrationEntry(entry *common.RegistrationEntry) *common.RegistrationEntry {
	resp, err := s.ds.CreateRegistrationEntry(context.Background(), &datastore.CreateRegistrationEntryRequest{
		Entry: entry,
	})
	s.Require().NoError(err)
	return resp.Entry
}

func (s *HandlerSuite) setNodeSelectors(spiffeID string, selectors []*common.Selector) {
	_, err := s.ds.SetNodeSelectors(context.Background(), &datastore.SetNodeSelectorsRequest{
		Selectors: &datastore.NodeSelectors{
			SpiffeId:  spiffeID,
			Selectors: selectors,
		},
	})
	s.Require().NoError(err)
}

func (s *HandlerSuite) requireErrorContains(err error, contains string) {
	requireErrorContains(s.T(), err, contains)
}

func (s *HandlerSuite) requireGRPCStatusCode(err error, code codes.Code) {
	requireGRPCStatusCode(s.T(), err, code)
}

func (s *HandlerSuite) requireNotGRPCStatusCode(err error, code codes.Code) {
	requireNotGRPCStatusCode(s.T(), err, code)
}

func pemBytes(p []byte) []byte {
	b, _ := pem.Decode(p)
	if b != nil {
		return b.Bytes
	}
	return nil
}

func requireErrorContains(t *testing.T, err error, contains string) {
	require.Error(t, err)
	require.Contains(t, err.Error(), contains)
}

func requireGRPCStatusCode(t *testing.T, err error, code codes.Code) {
	s := status.Convert(err)
	require.Equal(t, code, s.Code(), "GRPC status code should be %v", code)
}

func requireNotGRPCStatusCode(t *testing.T, err error, code codes.Code) {
	s := status.Convert(err)
	require.NotEqual(t, code, s.Code(), "GRPC status code should not be %v", code)
}
