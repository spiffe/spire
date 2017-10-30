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

type RegistrationServerTestSuite struct {
	suite.Suite
	t                  *testing.T
	ctrl               *gomock.Controller
	registrationServer *registrationServer
	mockCatalog        *mock_catalog.MockCatalog
	mockDataStore      *mock_datastore.MockDataStore
}

func SetupRegistrationTest(t *testing.T) *RegistrationServerTestSuite {
	suite := &RegistrationServerTestSuite{}
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
	suite := SetupRegistrationTest(t)
	defer suite.ctrl.Finish()

	//test data
	request := getRegistrationEntries()[0]
	createRequest := &datastore.CreateRegistrationEntryRequest{
		RegisteredEntry: request,
	}

	createResponse := &datastore.CreateRegistrationEntryResponse{
		RegisteredEntryId: "abcdefgh",
	}

	expectedResponse := &registration.RegistrationEntryID{
		Id: createResponse.RegisteredEntryId,
	}

	//expectations
	suite.mockCatalog.EXPECT().DataStores().
		Return([]datastore.DataStore{suite.mockDataStore})
	suite.mockDataStore.EXPECT().
		CreateRegistrationEntry(createRequest).
		Return(createResponse, nil)

	//exercise
	response, err := suite.registrationServer.CreateEntry(nil, request)

	//verification
	if !reflect.DeepEqual(response, expectedResponse) {
		t.Errorf("Response was incorrect\n Got: %v\n Want: %v\n",
			response, expectedResponse)
	}

	if err != nil {
		t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, nil)
	}
}

func TestCreateEntryError(t *testing.T) {
	suite := SetupRegistrationTest(t)
	defer suite.ctrl.Finish()

	//test data
	request := getRegistrationEntries()[0]
	createRequest := &datastore.CreateRegistrationEntryRequest{
		RegisteredEntry: request,
	}

	var expectedResponse *registration.RegistrationEntryID
	expectedError := errors.New("Error trying to create entry")

	//expectations
	suite.mockCatalog.EXPECT().DataStores().
		Return([]datastore.DataStore{suite.mockDataStore})
	suite.mockDataStore.EXPECT().
		CreateRegistrationEntry(createRequest).
		Return(nil, errors.New("foo"))

	//exercise
	response, err := suite.registrationServer.CreateEntry(nil, request)

	//verification
	if !reflect.DeepEqual(response, expectedResponse) {
		t.Errorf("CreateEntry(%v)\n Got: %v\n Want: %v\n",
			1, response, expectedResponse)
	}

	if !reflect.DeepEqual(err, expectedError) {
		t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, expectedError)
	}
}

func TestFetchEntry(t *testing.T) {
	suite := SetupRegistrationTest(t)
	defer suite.ctrl.Finish()

	//test data
	request := &registration.RegistrationEntryID{Id: "abcdefgh"}
	fetchRequest := &datastore.FetchRegistrationEntryRequest{
		RegisteredEntryId: request.Id,
	}

	fetchResponse := &datastore.FetchRegistrationEntryResponse{
		RegisteredEntry: getRegistrationEntries()[0],
	}

	expectedResponse := fetchResponse.RegisteredEntry

	//expectations
	suite.mockCatalog.EXPECT().DataStores().
		Return([]datastore.DataStore{suite.mockDataStore})
	suite.mockDataStore.EXPECT().
		FetchRegistrationEntry(fetchRequest).
		Return(fetchResponse, nil)

	//exercise
	response, err := suite.registrationServer.FetchEntry(nil, request)

	//verification
	if !reflect.DeepEqual(response, expectedResponse) {
		t.Errorf("Response was incorrect\n Got: %v\n Want: %v\n",
			response, expectedResponse)
	}

	if err != nil {
		t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, nil)
	}

}

func TestFetchEntryError(t *testing.T) {
	suite := SetupRegistrationTest(t)
	defer suite.ctrl.Finish()

	//test data
	request := &registration.RegistrationEntryID{Id: "abcdefgh"}
	fetchRequest := &datastore.FetchRegistrationEntryRequest{
		RegisteredEntryId: request.Id,
	}

	var expectedResponse *common.RegistrationEntry
	expectedResponse = nil
	expectedError := errors.New("Error trying to fetch entry")

	//expectations
	suite.mockCatalog.EXPECT().DataStores().
		Return([]datastore.DataStore{suite.mockDataStore})
	suite.mockDataStore.EXPECT().
		FetchRegistrationEntry(fetchRequest).
		Return(nil, errors.New("foo"))

	//exercise
	response, err := suite.registrationServer.FetchEntry(nil, request)

	//verification
	if !reflect.DeepEqual(response, expectedResponse) {
		t.Errorf("CreateEntry(%v)\n Got: %v\n Want: %v\n",
			1, response, expectedResponse)
	}

	if !reflect.DeepEqual(err, expectedError) {
		t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, expectedError)
	}

}

func TestListByParentID(t *testing.T) {
	suite := SetupRegistrationTest(t)
	defer suite.ctrl.Finish()

	//test data
	request := &registration.ParentID{
		Id: "spiffe://example.org/spire/agent/join_token/TokenBlog",
	}
	listRequest := &datastore.ListParentIDEntriesRequest{ParentId: request.Id}

	listResponse := &datastore.ListParentIDEntriesResponse{
		RegisteredEntryList: getRegistrationEntries(),
	}

	expectedResponse := &common.RegistrationEntries{
		Entries: listResponse.RegisteredEntryList,
	}

	//expectations
	suite.mockCatalog.EXPECT().DataStores().
		Return([]datastore.DataStore{suite.mockDataStore})
	suite.mockDataStore.EXPECT().
		ListParentIDEntries(listRequest).
		Return(listResponse, nil)

	//exercise
	response, err := suite.registrationServer.ListByParentID(nil, request)

	//verification
	if !reflect.DeepEqual(response, expectedResponse) {
		t.Errorf("Response was incorrect\n Got: %v\n Want: %v\n",
			response, expectedResponse)
	}

	if err != nil {
		t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, nil)
	}

}

func TestListByParentIDError(t *testing.T) {
	suite := SetupRegistrationTest(t)
	defer suite.ctrl.Finish()

	//test data
	request := &registration.ParentID{
		Id: "spiffe://example.org/spire/agent/join_token/TokenBlog",
	}
	listRequest := &datastore.ListParentIDEntriesRequest{ParentId: request.Id}

	var expectedResponse *common.RegistrationEntries
	expectedResponse = nil

	expectedError := errors.New("Error trying to list entries by parent ID")

	//expectations
	suite.mockCatalog.EXPECT().DataStores().
		Return([]datastore.DataStore{suite.mockDataStore})
	suite.mockDataStore.EXPECT().
		ListParentIDEntries(listRequest).
		Return(nil, errors.New("foo"))

	//exercise
	response, err := suite.registrationServer.ListByParentID(nil, request)

	//verification
	if !reflect.DeepEqual(response, expectedResponse) {
		t.Errorf("CreateEntry(%v)\n Got: %v\n Want: %v\n",
			1, response, expectedResponse)
	}

	if !reflect.DeepEqual(err, expectedError) {
		t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, expectedError)
	}

}

func TestCreateJoinToken(t *testing.T) {
	suite := SetupRegistrationTest(t)
	defer suite.ctrl.Finish()

	//test data
	request := &registration.JoinToken{Token: "123abc", Ttl: 200}
	registerTokenRequest := gomock.Any()
	registerTokenResponse := &common.Empty{}
	expectedResponse := request

	//expectations
	suite.mockCatalog.EXPECT().DataStores().
		Return([]datastore.DataStore{suite.mockDataStore})
	suite.mockDataStore.EXPECT().
		RegisterToken(registerTokenRequest).
		Return(registerTokenResponse, nil)

	//exercise
	response, err := suite.registrationServer.CreateJoinToken(nil, request)

	//verification
	if !reflect.DeepEqual(response, expectedResponse) {
		t.Errorf("Response was incorrect\n Got: %v\n Want: %v\n",
			response, expectedResponse)
	}

	if err != nil {
		t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, nil)
	}
}

func TestCreateJoinTokenWithoutToken(t *testing.T) {
	suite := SetupRegistrationTest(t)
	defer suite.ctrl.Finish()

	//test data
	request := &registration.JoinToken{Ttl: 200}
	registerTokenRequest := gomock.Any()
	registerTokenResponse := &common.Empty{}

	//expectations
	suite.mockCatalog.EXPECT().DataStores().
		Return([]datastore.DataStore{suite.mockDataStore})
	suite.mockDataStore.EXPECT().
		RegisterToken(registerTokenRequest).
		Return(registerTokenResponse, nil)

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

func TestCreateJoinTokenWithoutTtl(t *testing.T) {
	suite := SetupRegistrationTest(t)
	defer suite.ctrl.Finish()

	//test data
	request := &registration.JoinToken{}

	//exercise
	response, err := suite.registrationServer.CreateJoinToken(nil, request)

	//expectations
	var expectedResponse *registration.JoinToken
	expectedResponse = nil
	expectedError := errors.New("Ttl is required, you must provide one")

	//verification
	if !reflect.DeepEqual(response, expectedResponse) {
		t.Errorf("Response was incorrect\n Got: %v\n Want: %v\n",
			response, expectedResponse)
	}

	if !reflect.DeepEqual(err, expectedError) {
		t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, expectedError)
	}
}

func getRegistrationEntries() []*common.RegistrationEntry {
	regEntries := &common.RegistrationEntries{}
	dat, _ := ioutil.ReadFile("../../test/fixture/registration/good.json")
	json.Unmarshal(dat, &regEntries)
	return regEntries.Entries
}
