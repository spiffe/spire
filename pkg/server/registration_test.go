package server

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/test/mock/proto/server/datastore"
	"github.com/spiffe/spire/test/mock/server/catalog"
	"github.com/stretchr/testify/suite"
)

type registrationServerTestSuite struct {
	suite.Suite
	t                  *testing.T
	ctrl               *gomock.Controller
	registrationServer *registrationServer
	mockCatalog        *mock_catalog.MockCatalog
	mockDataStore      *mock_datastore.MockDataStore
}

func setupRegistrationTest(t *testing.T) *registrationServerTestSuite {
	suite := &registrationServerTestSuite{}
	mockCtrl := gomock.NewController(t)
	suite.ctrl = mockCtrl
	log, _ := test.NewNullLogger()
	suite.mockCatalog = mock_catalog.NewMockCatalog(mockCtrl)
	suite.mockDataStore = mock_datastore.NewMockDataStore(mockCtrl)

	suite.registrationServer = &registrationServer{
		l:       log,
		catalog: suite.mockCatalog,
	}
	return suite
}

func TestCreateEntry(t *testing.T) {

	goodRequest := getRegistrationEntries()[0]
	goodResponse := &registration.RegistrationEntryID{
		Id: "abcdefgh",
	}

	var testCases = []struct {
		request          *common.RegistrationEntry
		expectedResponse *registration.RegistrationEntryID
		expectedError    error
		setExpectations  func(*registrationServerTestSuite)
	}{
		{goodRequest, goodResponse, nil, createEntryExpectations},
		{goodRequest, nil, errors.New("Error trying to create entry"), createEntryErrorExpectations},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)

		tt.setExpectations(suite)
		response, err := suite.registrationServer.CreateEntry(nil, tt.request)

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
	var testCases = []struct {
		request          *registration.RegistrationEntryID
		expectedResponse *common.RegistrationEntry
		expectedError    error
		setExpectations  func(*registrationServerTestSuite)
	}{
		{nil, nil, nil, func(*registrationServerTestSuite) {}},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)
		tt.setExpectations(suite)
		response, err := suite.registrationServer.DeleteEntry(nil, tt.request)

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
	goodResponse := getRegistrationEntries()[0]

	var testCases = []struct {
		request          *registration.RegistrationEntryID
		expectedResponse *common.RegistrationEntry
		expectedError    error
		setExpectations  func(*registrationServerTestSuite)
	}{
		{goodRequest, goodResponse, nil, fetchEntryExpectations},
		{goodRequest, nil, errors.New("Error trying to fetch entry"), fetchEntryErrorExpectations},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)

		tt.setExpectations(suite)
		response, err := suite.registrationServer.FetchEntry(nil, tt.request)

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
		setExpectations  func(*registrationServerTestSuite)
	}{
		{nil, nil, nil, func(*registrationServerTestSuite) {}},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)
		tt.setExpectations(suite)
		response, err := suite.registrationServer.UpdateEntry(nil, tt.request)

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
		Entries: getRegistrationEntries(),
	}
	var testCases = []struct {
		request          *registration.ParentID
		expectedResponse *common.RegistrationEntries
		expectedError    error
		setExpectations  func(*registrationServerTestSuite)
	}{
		{goodRequest, goodResponse, nil, listByParentIDExpectations},
		{goodRequest, nil, errors.New("Error trying to list entries by parent ID"), listByParentIDErrorExpectations},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)

		tt.setExpectations(suite)
		response, err := suite.registrationServer.ListByParentID(nil, tt.request)

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
	var testCases = []struct {
		request          *common.Selector
		expectedResponse *common.RegistrationEntries
		expectedError    error
		setExpectations  func(*registrationServerTestSuite)
	}{
		{nil, nil, nil, func(*registrationServerTestSuite) {}},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)
		tt.setExpectations(suite)
		response, err := suite.registrationServer.ListBySelector(nil, tt.request)

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
	var testCases = []struct {
		request          *registration.SpiffeID
		expectedResponse *common.RegistrationEntries
		expectedError    error
		setExpectations  func(*registrationServerTestSuite)
	}{
		{nil, nil, nil, func(*registrationServerTestSuite) {}},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)
		tt.setExpectations(suite)
		response, err := suite.registrationServer.ListBySpiffeID(nil, tt.request)

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

func TestCreateFederatedBundle(t *testing.T) {
	var testCases = []struct {
		request          *registration.CreateFederatedBundleRequest
		expectedResponse *common.Empty
		expectedError    error
		setExpectations  func(*registrationServerTestSuite)
	}{
		{nil, nil, nil, func(*registrationServerTestSuite) {}},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)
		tt.setExpectations(suite)
		response, err := suite.registrationServer.CreateFederatedBundle(nil, tt.request)

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

func TestListFederatedBundles(t *testing.T) {
	var testCases = []struct {
		request          *common.Empty
		expectedResponse *registration.ListFederatedBundlesReply
		expectedError    error
		setExpectations  func(*registrationServerTestSuite)
	}{
		{nil, nil, nil, func(*registrationServerTestSuite) {}},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)
		tt.setExpectations(suite)
		response, err := suite.registrationServer.ListFederatedBundles(nil, tt.request)

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

func TestUpdateFederatedBundle(t *testing.T) {
	var testCases = []struct {
		request          *registration.FederatedBundle
		expectedResponse *common.Empty
		expectedError    error
		setExpectations  func(*registrationServerTestSuite)
	}{
		{nil, nil, nil, func(*registrationServerTestSuite) {}},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)
		tt.setExpectations(suite)
		response, err := suite.registrationServer.UpdateFederatedBundle(nil, tt.request)

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

func TestDeleteFederatedBundle(t *testing.T) {
	var testCases = []struct {
		request          *registration.FederatedSpiffeID
		expectedResponse *common.Empty
		expectedError    error
		setExpectations  func(*registrationServerTestSuite)
	}{
		{nil, nil, nil, func(*registrationServerTestSuite) {}},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)
		tt.setExpectations(suite)
		response, err := suite.registrationServer.DeleteFederatedBundle(nil, tt.request)

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
		setExpectations  func(*registrationServerTestSuite)
	}{
		{goodRequest, goodResponse, nil, createJoinTokenExpectations},
		{&registration.JoinToken{}, nil, errors.New("Ttl is required, you must provide one"), noExpectations},
		{&registration.JoinToken{Token: "123abc"}, nil, errors.New("Ttl is required, you must provide one"), noExpectations},
		{goodRequest, nil, errors.New("Error trying to register your token"), createJoinTokenErrorExpectations},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)

		tt.setExpectations(suite)
		response, err := suite.registrationServer.CreateJoinToken(nil, tt.request)

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
	suite.mockCatalog.EXPECT().DataStores().
		Return([]datastore.DataStore{suite.mockDataStore})
	suite.mockDataStore.EXPECT().
		RegisterToken(gomock.Any()).
		Return(&common.Empty{}, nil)

	//exercise
	response, err := suite.registrationServer.CreateJoinToken(nil, request)

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

func noExpectations(*registrationServerTestSuite) {}

func createEntryExpectations(suite *registrationServerTestSuite) {
	expectDataStore(suite)

	createRequest := &datastore.CreateRegistrationEntryRequest{
		RegisteredEntry: getRegistrationEntries()[0],
	}

	createResponse := &datastore.CreateRegistrationEntryResponse{
		RegisteredEntryId: "abcdefgh",
	}

	suite.mockDataStore.EXPECT().
		CreateRegistrationEntry(createRequest).
		Return(createResponse, nil)
}

func createEntryErrorExpectations(suite *registrationServerTestSuite) {
	expectDataStore(suite)

	suite.mockDataStore.EXPECT().
		CreateRegistrationEntry(gomock.Any()).
		Return(nil, errors.New("foo"))
}

func fetchEntryExpectations(suite *registrationServerTestSuite) {
	expectDataStore(suite)

	fetchRequest := &datastore.FetchRegistrationEntryRequest{
		RegisteredEntryId: "abcdefgh",
	}
	fetchResponse := &datastore.FetchRegistrationEntryResponse{
		RegisteredEntry: getRegistrationEntries()[0],
	}
	suite.mockDataStore.EXPECT().
		FetchRegistrationEntry(fetchRequest).
		Return(fetchResponse, nil)
}

func fetchEntryErrorExpectations(suite *registrationServerTestSuite) {
	expectDataStore(suite)

	suite.mockDataStore.EXPECT().
		FetchRegistrationEntry(gomock.Any()).
		Return(nil, errors.New("foo"))
}

func listByParentIDExpectations(suite *registrationServerTestSuite) {
	expectDataStore(suite)

	listRequest := &datastore.ListParentIDEntriesRequest{ParentId: "spiffe://example.org/spire/agent/join_token/TokenBlog"}
	listResponse := &datastore.ListParentIDEntriesResponse{
		RegisteredEntryList: getRegistrationEntries(),
	}
	suite.mockDataStore.EXPECT().
		ListParentIDEntries(listRequest).
		Return(listResponse, nil)
}

func listByParentIDErrorExpectations(suite *registrationServerTestSuite) {
	expectDataStore(suite)

	suite.mockDataStore.EXPECT().
		ListParentIDEntries(gomock.Any()).
		Return(nil, errors.New("foo"))
}

func createJoinTokenExpectations(suite *registrationServerTestSuite) {
	expectDataStore(suite)

	suite.mockDataStore.EXPECT().
		RegisterToken(gomock.Any()).
		Return(&common.Empty{}, nil)
}

func createJoinTokenErrorExpectations(suite *registrationServerTestSuite) {
	expectDataStore(suite)

	suite.mockDataStore.EXPECT().
		RegisterToken(gomock.Any()).
		Return(nil, errors.New("foo"))
}

func expectDataStore(suite *registrationServerTestSuite) {
	suite.mockCatalog.EXPECT().DataStores().
		Return([]datastore.DataStore{suite.mockDataStore})
}

func getRegistrationEntries() []*common.RegistrationEntry {
	regEntries := &common.RegistrationEntries{}
	dat, _ := ioutil.ReadFile("../../test/fixture/registration/good.json")
	json.Unmarshal(dat, &regEntries)
	return regEntries.Entries
}
