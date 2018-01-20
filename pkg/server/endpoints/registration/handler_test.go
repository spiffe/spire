package registration

import (
	"errors"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/test/mock/proto/server/datastore"
	"github.com/spiffe/spire/test/mock/server/catalog"
	testutil "github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/suite"
)

type handlerTestSuite struct {
	suite.Suite
	t                  *testing.T
	ctrl               *gomock.Controller
	handler            *Handler
	mockCatalog        *mock_catalog.MockCatalog
	mockDataStore      *mock_datastore.MockDataStore
}

func setupRegistrationTest(t *testing.T) *handlerTestSuite {
	suite := &handlerTestSuite{}
	mockCtrl := gomock.NewController(t)
	suite.ctrl = mockCtrl
	log, _ := test.NewNullLogger()
	suite.mockCatalog = mock_catalog.NewMockCatalog(mockCtrl)
	suite.mockDataStore = mock_datastore.NewMockDataStore(mockCtrl)

	suite.handler = &Handler{
		Log:     log,
		Catalog: suite.mockCatalog,
	}
	return suite
}

func TestCreateEntry(t *testing.T) {

	goodRequest := testutil.GetRegistrationEntries("good.json")[0]
	goodResponse := &registration.RegistrationEntryID{
		Id: "abcdefgh",
	}

	var testCases = []struct {
		request          *common.RegistrationEntry
		expectedResponse *registration.RegistrationEntryID
		expectedError    error
		setExpectations  func(*handlerTestSuite)
	}{
		{goodRequest, goodResponse, nil, createEntryExpectations},
		{goodRequest, nil, errors.New("Error trying to create entry"), createEntryErrorExpectations},
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

func TestCreateFederatedBundle(t *testing.T) {
	var testCases = []struct {
		request          *registration.CreateFederatedBundleRequest
		expectedResponse *common.Empty
		expectedError    error
		setExpectations  func(*handlerTestSuite)
	}{
		{nil, nil, nil, func(*handlerTestSuite) {}},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)
		tt.setExpectations(suite)
		response, err := suite.handler.CreateFederatedBundle(nil, tt.request)

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
		setExpectations  func(*handlerTestSuite)
	}{
		{nil, nil, nil, func(*handlerTestSuite) {}},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)
		tt.setExpectations(suite)
		response, err := suite.handler.ListFederatedBundles(nil, tt.request)

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
		setExpectations  func(*handlerTestSuite)
	}{
		{nil, nil, nil, func(*handlerTestSuite) {}},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)
		tt.setExpectations(suite)
		response, err := suite.handler.UpdateFederatedBundle(nil, tt.request)

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
		setExpectations  func(*handlerTestSuite)
	}{
		{nil, nil, nil, func(*handlerTestSuite) {}},
	}

	for _, tt := range testCases {
		suite := setupRegistrationTest(t)
		tt.setExpectations(suite)
		response, err := suite.handler.DeleteFederatedBundle(nil, tt.request)

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
	suite.mockCatalog.EXPECT().DataStores().
		Return([]datastore.DataStore{suite.mockDataStore})
	suite.mockDataStore.EXPECT().
		RegisterToken(gomock.Any()).
		Return(&common.Empty{}, nil)

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

func noExpectations(*handlerTestSuite) {}

func createEntryExpectations(suite *handlerTestSuite) {
	expectDataStore(suite)

	createRequest := &datastore.CreateRegistrationEntryRequest{
		RegisteredEntry: testutil.GetRegistrationEntries("good.json")[0],
	}

	createResponse := &datastore.CreateRegistrationEntryResponse{
		RegisteredEntryId: "abcdefgh",
	}

	suite.mockDataStore.EXPECT().
		CreateRegistrationEntry(createRequest).
		Return(createResponse, nil)
}

func createEntryErrorExpectations(suite *handlerTestSuite) {
	expectDataStore(suite)

	suite.mockDataStore.EXPECT().
		CreateRegistrationEntry(gomock.Any()).
		Return(nil, errors.New("foo"))
}

func fetchEntryExpectations(suite *handlerTestSuite) {
	expectDataStore(suite)

	fetchRequest := &datastore.FetchRegistrationEntryRequest{
		RegisteredEntryId: "abcdefgh",
	}
	fetchResponse := &datastore.FetchRegistrationEntryResponse{
		RegisteredEntry: testutil.GetRegistrationEntries("good.json")[0],
	}
	suite.mockDataStore.EXPECT().
		FetchRegistrationEntry(fetchRequest).
		Return(fetchResponse, nil)
}

func fetchEntriesExpectations(suite *handlerTestSuite) {
	expectDataStore(suite)

	fetchResponse := &datastore.FetchRegistrationEntriesResponse{
		RegisteredEntries: &common.RegistrationEntries{
			testutil.GetRegistrationEntries("good.json"),
		},
	}
	suite.mockDataStore.EXPECT().
		FetchRegistrationEntries(&common.Empty{}).
		Return(fetchResponse, nil)
}

func fetchEntryErrorExpectations(suite *handlerTestSuite) {
	expectDataStore(suite)

	suite.mockDataStore.EXPECT().
		FetchRegistrationEntry(gomock.Any()).
		Return(nil, errors.New("foo"))
}

func deleteEntryExpectations(suite *handlerTestSuite) {
	expectDataStore(suite)

	resp := &datastore.DeleteRegistrationEntryResponse{
		RegisteredEntry: testutil.GetRegistrationEntries("good.json")[0],
	}

	suite.mockDataStore.EXPECT().
		DeleteRegistrationEntry(gomock.Any()).
		Return(resp, nil)
}

func listByParentIDExpectations(suite *handlerTestSuite) {
	expectDataStore(suite)

	listRequest := &datastore.ListParentIDEntriesRequest{ParentId: "spiffe://example.org/spire/agent/join_token/TokenBlog"}
	listResponse := &datastore.ListParentIDEntriesResponse{
		RegisteredEntryList: testutil.GetRegistrationEntries("good.json"),
	}
	suite.mockDataStore.EXPECT().
		ListParentIDEntries(listRequest).
		Return(listResponse, nil)
}

func listByParentIDErrorExpectations(suite *handlerTestSuite) {
	expectDataStore(suite)

	suite.mockDataStore.EXPECT().
		ListParentIDEntries(gomock.Any()).
		Return(nil, errors.New("foo"))
}

func listBySelectorExpectations(suite *handlerTestSuite) {
	expectDataStore(suite)

	req := &datastore.ListSelectorEntriesRequest{
		Selectors: []*common.Selector{
			{Type: "unix", Value: "uid:1111"},
		},
	}
	resp := &datastore.ListSelectorEntriesResponse{
		RegisteredEntryList: testutil.GetRegistrationEntries("good.json"),
	}

	suite.mockDataStore.EXPECT().
		ListSelectorEntries(req).
		Return(resp, nil)
}

func listBySpiffeIDExpectations(suite *handlerTestSuite) {
	expectDataStore(suite)

	req := &datastore.ListSpiffeEntriesRequest{
		SpiffeId: "spiffe://example.org/Blog",
	}

	resp := &datastore.ListSpiffeEntriesResponse{
		RegisteredEntryList: testutil.GetRegistrationEntries("good.json")[0:1],
	}

	suite.mockDataStore.EXPECT().
		ListSpiffeEntries(req).
		Return(resp, nil)
}

func createJoinTokenExpectations(suite *handlerTestSuite) {
	expectDataStore(suite)

	suite.mockDataStore.EXPECT().
		RegisterToken(gomock.Any()).
		Return(&common.Empty{}, nil)
}

func createJoinTokenErrorExpectations(suite *handlerTestSuite) {
	expectDataStore(suite)

	suite.mockDataStore.EXPECT().
		RegisterToken(gomock.Any()).
		Return(nil, errors.New("foo"))
}

func expectDataStore(suite *handlerTestSuite) {
	suite.mockCatalog.EXPECT().DataStores().
		Return([]datastore.DataStore{suite.mockDataStore})
}
