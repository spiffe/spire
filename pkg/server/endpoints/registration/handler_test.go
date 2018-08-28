package registration

import (
	"context"
	"errors"
	"net"
	"net/url"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/mock/proto/server/datastore"
	testutil "github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
)

func TestHandler(t *testing.T) {
	suite.Run(t, new(HandlerSuite))
}

type HandlerSuite struct {
	suite.Suite

	server *grpc.Server

	ds      *fakedatastore.DataStore
	handler registration.RegistrationClient
}

func (s *HandlerSuite) SetupTest() {
	log, _ := test.NewNullLogger()

	s.ds = fakedatastore.New()

	catalog := fakeservercatalog.New()
	catalog.SetDataStores(s.ds)

	handler := &Handler{
		Log:         log,
		TrustDomain: url.URL{Scheme: "spiffe", Host: "example.org"},
		Catalog:     catalog,
	}

	// we need to test a streaming API. without doing the same codegen we
	// did with plugins, implementing the server or client side interfaces
	// is a pain. start up a localhost server and test over that.
	s.server = grpc.NewServer()
	registration.RegisterRegistrationServer(s.server, handler)

	// start up a server over localhost
	listener, err := net.Listen("tcp", "localhost:0")
	s.Require().NoError(err)
	go s.server.Serve(listener)

	conn, err := grpc.Dial(listener.Addr().String(), grpc.WithInsecure())
	s.Require().NoError(err)

	s.handler = registration.NewRegistrationClient(conn)
}

func (s *HandlerSuite) TearDownTest() {
	s.server.Stop()
}

func (s *HandlerSuite) TestCreateFederatedBundle() {
	testCases := []struct {
		Id      string
		CaCerts string
		Err     string
	}{
		{Id: "spiffe://example.org", CaCerts: "", Err: "federated bundle id cannot match server trust domain"},
		{Id: "spiffe://otherdomain.org/spire/agent", CaCerts: "", Err: `"spiffe://otherdomain.org/spire/agent" is not a valid trust domain SPIFFE ID: path is not empty`},
		{Id: "spiffe://otherdomain.org", CaCerts: "CACERTS", Err: ""},
		{Id: "spiffe://otherdomain.org", CaCerts: "CACERTS", Err: "bundle already exists"},
	}

	for _, testCase := range testCases {
		response, err := s.handler.CreateFederatedBundle(context.Background(), &registration.FederatedBundle{
			SpiffeId: testCase.Id,
			CaCerts:  []byte(testCase.CaCerts),
		})

		if testCase.Err != "" {
			s.Require().Error(err)
			s.Require().Contains(err.Error(), testCase.Err)
			continue
		}
		s.Require().NoError(err)
		s.Require().Equal(&common.Empty{}, response)

		// assert that the bundle was created in the datastore
		resp, err := s.ds.FetchBundle(context.Background(), &datastore.FetchBundleRequest{
			TrustDomain: testCase.Id,
		})
		s.Require().NoError(err)
		s.Require().Equal(resp.Bundle.TrustDomain, testCase.Id)
		s.Require().Equal(string(resp.Bundle.CaCerts), testCase.CaCerts)
	}
}

func (s *HandlerSuite) TestFetchFederatedBundle() {
	// Create three bundles
	s.createBundle(&datastore.Bundle{
		TrustDomain: "spiffe://example.org",
		CaCerts:     []byte("EXAMPLE"),
	})
	s.createBundle(&datastore.Bundle{
		TrustDomain: "spiffe://otherdomain.org",
		CaCerts:     []byte("OTHERDOMAIN"),
	})

	testCases := []struct {
		Id      string
		CaCerts string
		Err     string
	}{
		{Id: "spiffe://example.org", CaCerts: "", Err: "federated bundle id cannot match server trust domain"},
		{Id: "spiffe://otherdomain.org/spire/agent", CaCerts: "", Err: `"spiffe://otherdomain.org/spire/agent" is not a valid trust domain SPIFFE ID: path is not empty`},
		{Id: "spiffe://otherdomain.org", CaCerts: "OTHERDOMAIN", Err: ""},
		{Id: "spiffe://yetotherdomain.org", CaCerts: "", Err: "no such bundle"},
	}

	for _, testCase := range testCases {
		response, err := s.handler.FetchFederatedBundle(context.Background(), &registration.FederatedBundleID{
			Id: testCase.Id,
		})

		if testCase.Err != "" {
			s.Require().Error(err)
			s.Require().Contains(err.Error(), testCase.Err)
			continue
		}
		s.Require().NoError(err)
		s.Require().NotNil(response)
		s.Require().Equal(response.SpiffeId, testCase.Id)
		s.Require().Equal(string(response.CaCerts), testCase.CaCerts)
	}
}

func (s *HandlerSuite) TestListFederatedBundles() {
	s.createBundle(&datastore.Bundle{
		TrustDomain: "spiffe://example.org",
		CaCerts:     []byte("EXAMPLE"),
	})
	s.createBundle(&datastore.Bundle{
		TrustDomain: "spiffe://example2.org",
		CaCerts:     []byte("EXAMPLE2"),
	})

	// Assert that the listing does not contain the bundle for the server
	// trust domain
	stream, err := s.handler.ListFederatedBundles(context.Background(), &common.Empty{})
	s.Require().NoError(err)

	bundle, err := stream.Recv()
	s.Require().NoError(err)
	s.Require().Equal(&registration.FederatedBundle{
		SpiffeId: "spiffe://example2.org",
		CaCerts:  []byte("EXAMPLE2"),
	}, bundle)

	_, err = stream.Recv()
	s.Require().EqualError(err, "EOF")
}

func (s *HandlerSuite) TestUpdateFederatedBundle() {
	testCases := []struct {
		Id      string
		CaCerts string
		Err     string
	}{
		{Id: "spiffe://example.org", CaCerts: "", Err: "federated bundle id cannot match server trust domain"},
		{Id: "spiffe://otherdomain.org/spire/agent", CaCerts: "", Err: `"spiffe://otherdomain.org/spire/agent" is not a valid trust domain SPIFFE ID: path is not empty`},
		{Id: "spiffe://otherdomain.org", CaCerts: "CACERTS", Err: ""},
		{Id: "spiffe://otherdomain.org", CaCerts: "CACERTS2", Err: ""},
	}

	for _, testCase := range testCases {
		response, err := s.handler.UpdateFederatedBundle(context.Background(), &registration.FederatedBundle{
			SpiffeId: testCase.Id,
			CaCerts:  []byte(testCase.CaCerts),
		})

		if testCase.Err != "" {
			s.Require().Error(err)
			s.Require().Contains(err.Error(), testCase.Err)
			continue
		}
		s.Require().NoError(err)
		s.Require().Equal(&common.Empty{}, response)

		// assert that the bundle was created in the datastore
		resp, err := s.ds.FetchBundle(context.Background(), &datastore.FetchBundleRequest{
			TrustDomain: testCase.Id,
		})
		s.Require().NoError(err)
		s.Require().Equal(resp.Bundle.TrustDomain, testCase.Id)
		s.Require().Equal(string(resp.Bundle.CaCerts), testCase.CaCerts)
	}
}

func (s *HandlerSuite) TestDeleteFederatedBundle() {
	testCases := []struct {
		Id  string
		Err string
	}{
		{Id: "spiffe://example.org", Err: "federated bundle id cannot match server trust domain"},
		{Id: "spiffe://otherdomain.org/spire/agent", Err: `"spiffe://otherdomain.org/spire/agent" is not a valid trust domain SPIFFE ID: path is not empty`},
		{Id: "spiffe://otherdomain.org", Err: ""},
		{Id: "spiffe://otherdomain.org", Err: "no such bundle"},
	}

	s.createBundle(&datastore.Bundle{
		TrustDomain: "spiffe://otherdomain.org",
		CaCerts:     []byte("BLAH"),
	})

	for _, testCase := range testCases {
		response, err := s.handler.DeleteFederatedBundle(context.Background(), &registration.FederatedBundleID{
			Id: testCase.Id,
		})

		if testCase.Err != "" {
			s.Require().Error(err)
			s.Require().Contains(err.Error(), testCase.Err)
			continue
		}
		s.Require().NoError(err)
		s.Require().Equal(&common.Empty{}, response)

		// assert that the bundle was deleted
		resp, err := s.ds.FetchBundle(context.Background(), &datastore.FetchBundleRequest{
			TrustDomain: testCase.Id,
		})
		s.Require().EqualError(err, "no such bundle")
		s.Require().Nil(resp)
	}
}

func (s *HandlerSuite) createBundle(bundle *datastore.Bundle) {
	_, err := s.ds.CreateBundle(context.Background(), &datastore.CreateBundleRequest{
		Bundle: bundle,
	})
	s.Require().NoError(err)
}

type handlerTestSuite struct {
	suite.Suite
	ctrl          *gomock.Controller
	handler       *Handler
	mockDataStore *mock_datastore.MockDataStore
}

func setupRegistrationTest(t *testing.T) *handlerTestSuite {
	suite := &handlerTestSuite{}
	mockCtrl := gomock.NewController(t)
	suite.ctrl = mockCtrl
	log, _ := test.NewNullLogger()
	suite.mockDataStore = mock_datastore.NewMockDataStore(mockCtrl)

	catalog := fakeservercatalog.New()
	catalog.SetDataStores(suite.mockDataStore)

	suite.handler = &Handler{
		Log:         log,
		TrustDomain: url.URL{Scheme: "spiffe", Host: "example.org"},
		Catalog:     catalog,
	}
	return suite
}

func TestCreateEntry(t *testing.T) {

	goodRequest := testutil.GetRegistrationEntries("good.json")[0]
	goodResponse := &registration.RegistrationEntryID{
		Id: "abcdefgh",
	}
	invalidRequest := testutil.GetRegistrationEntries("invalid.json")[0]

	var testCases = []struct {
		request          *common.RegistrationEntry
		expectedResponse *registration.RegistrationEntryID
		expectedError    error
		setExpectations  func(*handlerTestSuite)
	}{
		{goodRequest, goodResponse, nil, createEntryExpectations},
		{goodRequest, nil, errors.New("Error trying to create entry"), createEntryErrorExpectations},
		{goodRequest, nil, errors.New("Entry already exists"), createEntryNonUniqueExpectations},
		{invalidRequest, nil, errors.New("Error while validating provided Spiffe ID"), func(suite *handlerTestSuite) {}},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)

		tt.setExpectations(suite)
		response, err := suite.handler.CreateEntry(nil, tt.request)

		//verification
		if !reflect.DeepEqual(response, tt.expectedResponse) {
			t.Errorf("Response was incorrect\n Got: %v\n Want: %v\n", response, tt.expectedResponse)
		}

		if !reflect.DeepEqual(err, tt.expectedError) {
			t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, tt.expectedError)
		}
		suite.ctrl.Finish()
	}
}

func TestDeleteEntry(t *testing.T) {
	goodResponse := testutil.GetRegistrationEntries("good.json")[0]
	req := &registration.RegistrationEntryID{Id: "1234"}

	var testCases = []struct {
		request          *registration.RegistrationEntryID
		expectedResponse *common.RegistrationEntry
		expectedError    error
		setExpectations  func(*handlerTestSuite)
	}{
		{req, goodResponse, nil, deleteEntryExpectations},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)
		tt.setExpectations(suite)
		response, err := suite.handler.DeleteEntry(nil, tt.request)

		//verification
		if !reflect.DeepEqual(response, tt.expectedResponse) {
			t.Errorf("Response was incorrect\n Got: %v\n Want: %v\n", response, tt.expectedResponse)
		}

		if !reflect.DeepEqual(err, tt.expectedError) {
			t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, tt.expectedError)
		}
		suite.ctrl.Finish()
	}
}

func TestFetchEntry(t *testing.T) {

	goodRequest := &registration.RegistrationEntryID{Id: "abcdefgh"}
	goodResponse := testutil.GetRegistrationEntries("good.json")[0]

	var testCases = []struct {
		request          *registration.RegistrationEntryID
		expectedResponse *common.RegistrationEntry
		expectedError    error
		setExpectations  func(*handlerTestSuite)
	}{
		{goodRequest, goodResponse, nil, fetchEntryExpectations},
		{goodRequest, nil, errors.New("Error trying to fetch entry"), fetchEntryErrorExpectations},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)

		tt.setExpectations(suite)
		response, err := suite.handler.FetchEntry(nil, tt.request)

		//verification
		if !reflect.DeepEqual(response, tt.expectedResponse) {
			t.Errorf("Response was incorrect\n Got: %v\n Want: %v\n", response, tt.expectedResponse)
		}

		if !reflect.DeepEqual(err, tt.expectedError) {
			t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, tt.expectedError)
		}
		suite.ctrl.Finish()
	}

}

func TestFetchEntries(t *testing.T) {
	goodResponse := &common.RegistrationEntries{
		Entries: testutil.GetRegistrationEntries("good.json"),
	}

	var testCases = []struct {
		expectedResponse *common.RegistrationEntries
		expectedError    error
		setExpectations  func(*handlerTestSuite)
	}{
		{goodResponse, nil, fetchEntriesExpectations},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)

		tt.setExpectations(suite)
		response, err := suite.handler.FetchEntries(nil, &common.Empty{})

		//verification
		if !reflect.DeepEqual(response, tt.expectedResponse) {
			t.Errorf("Response was incorrect\n Got: %v\n Want: %v\n", response, tt.expectedResponse)
		}

		if !reflect.DeepEqual(err, tt.expectedError) {
			t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, tt.expectedError)
		}
		suite.ctrl.Finish()
	}

}

func TestUpdateEntry(t *testing.T) {
	var testCases = []struct {
		request          *registration.UpdateEntryRequest
		expectedResponse *common.RegistrationEntry
		expectedError    error
		setExpectations  func(*handlerTestSuite)
	}{
		{nil, nil, nil, func(*handlerTestSuite) {}},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)
		tt.setExpectations(suite)
		response, err := suite.handler.UpdateEntry(nil, tt.request)

		//verification
		if !reflect.DeepEqual(response, tt.expectedResponse) {
			t.Errorf("Response was incorrect\n Got: %v\n Want: %v\n", response, tt.expectedResponse)
		}

		if !reflect.DeepEqual(err, tt.expectedError) {
			t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, tt.expectedError)
		}
		suite.ctrl.Finish()
	}
}

func TestListByParentID(t *testing.T) {

	goodRequest := &registration.ParentID{
		Id: "spiffe://example.org/spire/agent/join_token/TokenBlog",
	}
	goodResponse := &common.RegistrationEntries{
		Entries: testutil.GetRegistrationEntries("good.json"),
	}
	var testCases = []struct {
		request          *registration.ParentID
		expectedResponse *common.RegistrationEntries
		expectedError    error
		setExpectations  func(*handlerTestSuite)
	}{
		{goodRequest, goodResponse, nil, listByParentIDExpectations},
		{goodRequest, nil, errors.New("Error trying to list entries by parent ID"), listByParentIDErrorExpectations},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)

		tt.setExpectations(suite)
		response, err := suite.handler.ListByParentID(nil, tt.request)

		//verification
		if !reflect.DeepEqual(response, tt.expectedResponse) {
			t.Errorf("Response was incorrect\n Got: %v\n Want: %v\n", response, tt.expectedResponse)
		}

		if !reflect.DeepEqual(err, tt.expectedError) {
			t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, tt.expectedError)
		}
		suite.ctrl.Finish()
	}

}

func TestListBySelector(t *testing.T) {
	req := &common.Selector{Type: "unix", Value: "uid:1111"}
	resp := &common.RegistrationEntries{
		Entries: testutil.GetRegistrationEntries("good.json"),
	}

	var testCases = []struct {
		request          *common.Selector
		expectedResponse *common.RegistrationEntries
		expectedError    error
		setExpectations  func(*handlerTestSuite)
	}{
		{req, resp, nil, listBySelectorExpectations},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)
		tt.setExpectations(suite)
		response, err := suite.handler.ListBySelector(nil, tt.request)

		//verification
		if !reflect.DeepEqual(response, tt.expectedResponse) {
			t.Errorf("Response was incorrect\n Got: %v\n Want: %v\n", response, tt.expectedResponse)
		}

		if !reflect.DeepEqual(err, tt.expectedError) {
			t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, tt.expectedError)
		}
		suite.ctrl.Finish()
	}
}

func TestListBySpiffeID(t *testing.T) {
	req := &registration.SpiffeID{
		Id: "spiffe://example.org/Blog",
	}
	resp := &common.RegistrationEntries{
		Entries: testutil.GetRegistrationEntries("good.json")[0:1],
	}

	var testCases = []struct {
		request          *registration.SpiffeID
		expectedResponse *common.RegistrationEntries
		expectedError    error
		setExpectations  func(*handlerTestSuite)
	}{
		{req, resp, nil, listBySpiffeIDExpectations},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)
		tt.setExpectations(suite)
		response, err := suite.handler.ListBySpiffeID(nil, tt.request)

		//verification
		if !reflect.DeepEqual(response, tt.expectedResponse) {
			t.Errorf("Response was incorrect\n Got: %v\n Want: %v\n", response, tt.expectedResponse)
		}

		if !reflect.DeepEqual(err, tt.expectedError) {
			t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, tt.expectedError)
		}
		suite.ctrl.Finish()
	}
}

func TestCreateJoinToken(t *testing.T) {
	goodRequest := &registration.JoinToken{Token: "123abc", Ttl: 200}
	goodResponse := goodRequest

	var testCases = []struct {
		request          *registration.JoinToken
		expectedResponse *registration.JoinToken
		expectedError    error
		setExpectations  func(*handlerTestSuite)
	}{
		{goodRequest, goodResponse, nil, createJoinTokenExpectations},
		{&registration.JoinToken{}, nil, errors.New("Ttl is required, you must provide one"), noExpectations},
		{&registration.JoinToken{Token: "123abc"}, nil, errors.New("Ttl is required, you must provide one"), noExpectations},
		{goodRequest, nil, errors.New("Error trying to register your token"), createJoinTokenErrorExpectations},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)

		tt.setExpectations(suite)
		response, err := suite.handler.CreateJoinToken(nil, tt.request)

		//verification
		if !reflect.DeepEqual(response, tt.expectedResponse) {
			t.Errorf("Response was incorrect\n Got: %v\n Want: %v\n", response, tt.expectedResponse)
		}

		if !reflect.DeepEqual(err, tt.expectedError) {
			t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, tt.expectedError)
		}
		suite.ctrl.Finish()
	}
}

//TODO: put this in the test table
func TestCreateJoinTokenWithoutToken(t *testing.T) {
	suite := setupRegistrationTest(t)
	defer suite.ctrl.Finish()

	request := &registration.JoinToken{Ttl: 200}

	//expectations
	suite.mockDataStore.EXPECT().
		CreateJoinToken(gomock.Any(), gomock.Any()).
		Return(&datastore.CreateJoinTokenResponse{}, nil)

	//exercise
	response, err := suite.handler.CreateJoinToken(nil, request)

	//verification
	if response.Token == "" {
		t.Errorf("Response was incorrect\n Got: empty token\n Want: a token value\n")

	}

	if response.Ttl != 200 {
		t.Errorf("Response was incorrect\n Got: %v\n Want: %v\n",
			response.Ttl, 200)

	}

	if err != nil {
		t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, nil)
	}
}

func TestFetchBundle(t *testing.T) {
	request := &common.Empty{}
	goodResponse := &registration.Bundle{CaCerts: []byte{1, 2, 3}}
	var testCases = []struct {
		request          *common.Empty
		expectedResponse *registration.Bundle
		expectedError    error
		setExpectations  func(*handlerTestSuite)
	}{
		{request, goodResponse, nil, createFetchBundleExpectations},
		{request, nil, errors.New("get bundle from datastore: bundle not found"), createFetchBundleErrorExpectations},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)

		tt.setExpectations(suite)
		response, err := suite.handler.FetchBundle(nil, tt.request)

		//verification
		if !reflect.DeepEqual(response, tt.expectedResponse) {
			t.Errorf("Response was incorrect\n Got: %v\n Want: %v\n", response, tt.expectedResponse)
		}

		if !reflect.DeepEqual(err, tt.expectedError) {
			t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, tt.expectedError)
		}
		suite.ctrl.Finish()
	}
}

func noExpectations(*handlerTestSuite) {}

func createEntryExpectations(suite *handlerTestSuite) {
	entryIn := testutil.GetRegistrationEntries("good.json")[0]

	suite.mockDataStore.EXPECT().
		ListRegistrationEntries(gomock.Any(), &datastore.ListRegistrationEntriesRequest{BySpiffeId: &wrappers.StringValue{Value: entryIn.SpiffeId}}).
		Return(&datastore.ListRegistrationEntriesResponse{
			Entries: []*common.RegistrationEntry{},
		}, nil)

	createRequest := &datastore.CreateRegistrationEntryRequest{
		Entry: entryIn,
	}

	entryOut := *entryIn
	entryOut.EntryId = "abcdefgh"
	createResponse := &datastore.CreateRegistrationEntryResponse{
		Entry: &entryOut,
	}

	suite.mockDataStore.EXPECT().
		CreateRegistrationEntry(gomock.Any(), createRequest).
		Return(createResponse, nil)
}

func createEntryErrorExpectations(suite *handlerTestSuite) {
	suite.mockDataStore.EXPECT().
		ListRegistrationEntries(gomock.Any(), gomock.Any()).
		Return(&datastore.ListRegistrationEntriesResponse{
			Entries: []*common.RegistrationEntry{},
		}, nil)

	suite.mockDataStore.EXPECT().
		CreateRegistrationEntry(gomock.Any(), gomock.Any()).
		Return(nil, errors.New("foo"))
}

func createEntryNonUniqueExpectations(suite *handlerTestSuite) {
	newRegEntry := testutil.GetRegistrationEntries("good.json")[0]

	suite.mockDataStore.EXPECT().
		ListRegistrationEntries(gomock.Any(), &datastore.ListRegistrationEntriesRequest{
			BySpiffeId: &wrappers.StringValue{
				Value: newRegEntry.SpiffeId,
			},
		}).
		Return(&datastore.ListRegistrationEntriesResponse{
			Entries: []*common.RegistrationEntry{newRegEntry},
		}, nil)
}

func fetchEntryExpectations(suite *handlerTestSuite) {
	fetchRequest := &datastore.FetchRegistrationEntryRequest{
		EntryId: "abcdefgh",
	}
	fetchResponse := &datastore.FetchRegistrationEntryResponse{
		Entry: testutil.GetRegistrationEntries("good.json")[0],
	}
	suite.mockDataStore.EXPECT().
		FetchRegistrationEntry(gomock.Any(), fetchRequest).
		Return(fetchResponse, nil)
}

func fetchEntriesExpectations(suite *handlerTestSuite) {
	fetchResponse := &datastore.ListRegistrationEntriesResponse{
		Entries: testutil.GetRegistrationEntries("good.json"),
	}
	suite.mockDataStore.EXPECT().
		ListRegistrationEntries(gomock.Any(), &datastore.ListRegistrationEntriesRequest{}).
		Return(fetchResponse, nil)
}

func fetchEntryErrorExpectations(suite *handlerTestSuite) {
	suite.mockDataStore.EXPECT().
		FetchRegistrationEntry(gomock.Any(), gomock.Any()).
		Return(nil, errors.New("foo"))
}

func deleteEntryExpectations(suite *handlerTestSuite) {
	resp := &datastore.DeleteRegistrationEntryResponse{
		Entry: testutil.GetRegistrationEntries("good.json")[0],
	}

	suite.mockDataStore.EXPECT().
		DeleteRegistrationEntry(gomock.Any(), gomock.Any()).
		Return(resp, nil)
}

func listByParentIDExpectations(suite *handlerTestSuite) {
	listRequest := &datastore.ListRegistrationEntriesRequest{
		ByParentId: &wrappers.StringValue{
			Value: "spiffe://example.org/spire/agent/join_token/TokenBlog",
		},
	}
	listResponse := &datastore.ListRegistrationEntriesResponse{
		Entries: testutil.GetRegistrationEntries("good.json"),
	}
	suite.mockDataStore.EXPECT().
		ListRegistrationEntries(gomock.Any(), listRequest).
		Return(listResponse, nil)
}

func listByParentIDErrorExpectations(suite *handlerTestSuite) {
	suite.mockDataStore.EXPECT().
		ListRegistrationEntries(gomock.Any(), gomock.Any()).
		Return(nil, errors.New("foo"))
}

func listBySelectorExpectations(suite *handlerTestSuite) {
	req := &datastore.ListRegistrationEntriesRequest{
		BySelectors: &datastore.BySelectors{
			Selectors: []*common.Selector{{Type: "unix", Value: "uid:1111"}},
		},
	}
	resp := &datastore.ListRegistrationEntriesResponse{
		Entries: testutil.GetRegistrationEntries("good.json"),
	}

	suite.mockDataStore.EXPECT().
		ListRegistrationEntries(gomock.Any(), req).
		Return(resp, nil)
}

func listBySpiffeIDExpectations(suite *handlerTestSuite) {
	req := &datastore.ListRegistrationEntriesRequest{
		BySpiffeId: &wrappers.StringValue{
			Value: "spiffe://example.org/Blog",
		},
	}

	resp := &datastore.ListRegistrationEntriesResponse{
		Entries: testutil.GetRegistrationEntries("good.json")[0:1],
	}

	suite.mockDataStore.EXPECT().
		ListRegistrationEntries(gomock.Any(), req).
		Return(resp, nil)
}

func createJoinTokenExpectations(suite *handlerTestSuite) {
	suite.mockDataStore.EXPECT().
		CreateJoinToken(gomock.Any(), gomock.Any()).
		Return(&datastore.CreateJoinTokenResponse{}, nil)
}

func createJoinTokenErrorExpectations(suite *handlerTestSuite) {
	suite.mockDataStore.EXPECT().
		CreateJoinToken(gomock.Any(), gomock.Any()).
		Return(nil, errors.New("foo"))
}

func createFetchBundleExpectations(suite *handlerTestSuite) {
	suite.mockDataStore.EXPECT().
		FetchBundle(gomock.Any(), &datastore.FetchBundleRequest{
			TrustDomain: "spiffe://example.org",
		}).
		Return(&datastore.FetchBundleResponse{
			Bundle: &datastore.Bundle{CaCerts: []byte{1, 2, 3}},
		}, nil)
}

func createFetchBundleErrorExpectations(suite *handlerTestSuite) {
	suite.mockDataStore.EXPECT().
		FetchBundle(gomock.Any(), &datastore.FetchBundleRequest{
			TrustDomain: "spiffe://example.org",
		}).
		Return(nil, errors.New("bundle not found"))
}
