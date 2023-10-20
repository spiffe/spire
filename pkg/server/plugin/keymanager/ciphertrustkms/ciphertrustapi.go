package ciphertrustkms

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/status"
)

const (
	DefaultCATTL           = 24 * time.Hour
	AndParamSeparator      = "&"
	QueryParamSeparator    = "?"
	JsonType               = "application/json"
	OctetStreamContentType = "application/octet-stream"
	UrlEncodedContentType  = "application/x-www-form-urlencoded"
	AllTypeAccept          = "*/*"
	TextTypeAccept         = "text/plain"
	METHODPOST             = "POST"
	METHODGET              = "GET"
	METHODPATCH            = "PATCH"
	METHODDELETE           = "DELETE"
)

var USERNAME string
var PASSWORD string
var CTMSERVICE string

type CipherTrustInterfaceApi interface {
	ListCryptoKeys(ctx context.Context, limit string, algo string, curveid string, labels string) (*CipherTrustCryptoKeysList, error)
}

type AccessToken struct {
	Jwt       string  `json:"jwt,omitempty"`
	Duration  float64 `json:"duration,omitempty"`
	TokenType string  `json:"token_type,omitempty"`
}

type clientApi struct{}

type KeyIterator interface {
	hasNext() bool
	getNext() (*Key, bool)
}

type KeyCollection interface {
	createKeyIterator() KeyIterator
}

type CipherTrustCryptoKeysList struct {
	Keys []*Key `json:"resources,omitempty"`
}

type CipherTrustCryptoKeysListIterator struct {
	index int
	Keys  []*Key `json:"resources,omitempty"`
}

func (k *CipherTrustCryptoKeysList) createKeyIterator() KeyIterator {
	return &CipherTrustCryptoKeysListIterator{
		Keys: k.Keys,
	}
}

func (k *CipherTrustCryptoKeysListIterator) hasNext() bool {
	if k.index < len(k.Keys) {
		return true
	}
	return false
}
func (k *CipherTrustCryptoKeysListIterator) getNext() (*Key, bool) {
	if k.hasNext() {
		key := k.Keys[k.index]
		k.index++
		return key, true
	}
	return nil, false
}

type CipherTrustCryptoKey struct {
	Key Key `json:"resources,omitempty"`
}

type CipherTrustCryptoKeyVersion struct {
	CryptoKeys []Key `json:"resources,omitempty"`
}

func Init(ctmService string, username string, password string) {
	CTMSERVICE = ctmService
	USERNAME = username
	PASSWORD = password
}

func TokenGenerator() (*AccessToken, error) {
	EndPoint := CTMSERVICE + "/api/v1/auth/tokens"
	InputPayload := strings.NewReader("grant_type=password&username=" + USERNAME + "&password=" + PASSWORD)

	return NetworkHelperForToken(METHODPOST, EndPoint, InputPayload, UrlEncodedContentType)
}

// Not used yet
func (c *clientApi) deleteExistingKeys(ctx context.Context, keyId string) (bool, error) {
	g, ctx := errgroup.WithContext(ctx)

	KeyList, err := c.ListCryptoKeys(ctx, "")
	if err != nil {
		fmt.Println("Error geting the key to cleared")
		return false, err
	}

	it := KeyList.createKeyIterator()
	for {
		key, ok := it.getNext()
		if !ok {
			break
		}
		if strings.Contains(key.Name, keyId) {
			// Trigger a goroutine to delete key
			g.Go(func() error {
				ok, err := DeleteKey(key.ID)
				if err != nil || !ok {
					return err
				}
				return nil
			})
		}
	}
	// Wait for all the detail gathering routines to finish.
	if err := g.Wait(); err != nil {
		statusErr := status.Convert(err)
		return false, status.Errorf(statusErr.Code(), "failed to fetch entries: %v", statusErr.Message())
	}
	return true, nil
}

func DeleteKey(keyId string) (bool, error) {
	EndPoint := CTMSERVICE + "/api/v1/vault/keys2/" + keyId
	return NetworkHelperForDeleteKey(METHODDELETE, EndPoint)
}
func (c *clientApi) CreateKey(spireID string, labels map[string]string) (*CipherTrustCryptoKey, error) {
	EndPoint := CTMSERVICE + "/api/v1/vault/keys2"
	activation_date := time.Now()

	//Add 10 seconds to activation time to assign to buffer
	deactivation_buffer := activation_date.Add(time.Second * time.Duration(10))
	//Add one hour to buffer  to assign to deactivation time as a ca_ttl
	deactivation_date := deactivation_buffer.Add(DefaultCATTL)
	deactivation_dateTime_string := deactivation_date.Format(time.RFC3339Nano)
	fmt.Println("deactivation date=" + deactivation_dateTime_string)

	InputPayload := strings.NewReader(`{ "name":` + "\"" + spireID + "\"" + `,` + `
        "algorithm": "ec",` + "" + `
        "curveid": "prime256v1",` + `
        "deactivationDate":` + "\"" + deactivation_dateTime_string + "\"" + `,` + `
        "aliases": [{` + "" + `
            "alias":` + "\"" + spireID + "\"" + `,` + `
            "type": "string" }  ],` + `
        "labels": {` + "" + `
              "spire-active": ` + "\"" + labels["spire-active"] + "\"" + `,` + `
              "spire-server-id":` + "\"" + labels["spire-server-id"] + "\"" + `,` + `
              "spire-server-td":` + "\"" + labels["spire-server-td"] + "\"" + `` + `
        }  }`)

	return NetworkHelperForCreateKey(METHODPOST, EndPoint, InputPayload, JsonType)

}

// To list keys by key name
// key_name: Represent the name of the key
// Returns an array of Key structure otherwise error
func ListKeysByName(keyName string) (*CipherTrustCryptoKeysList, error) {
	EndPoint := CTMSERVICE + "/api/v1/vault/keys2"
	LimitParam := "limit=0"
	nameParam := "name="

	Query := QueryParamSeparator + LimitParam + AndParamSeparator + nameParam + keyName
	InputUrl := EndPoint + Query

	keys, err := NetworkHelperForListKeysByName(METHODGET, InputUrl, JsonType)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return keys, nil
}

func (c *clientApi) ListCryptoKeys(ctx context.Context, labels string) (*CipherTrustCryptoKeysList, error) {
	EndPoint := CTMSERVICE + "/api/v1/vault/keys2"
	LimitParam := "skip=0"
	curveidParam := "curveid=prime256v1"
	algoParam := "algorithm=EC"

	Query := QueryParamSeparator + LimitParam + AndParamSeparator + curveidParam + AndParamSeparator + algoParam + labels
	InputUrl := EndPoint + Query

	return NetworkHelperForListKeys(METHODGET, InputUrl, JsonType)
}

func (c *clientApi) SignMessage(keyName string, keyVersion int, data []byte) (*SignResponse, error) {
	EndPoint := CTMSERVICE + "/api/v1/crypto/sign"
	NameParam := "keyName=" + keyName
	VersionParam := "version=" + strconv.Itoa(keyVersion)
	SignParam := "signAlgo=ECDSA"
	HashParam := "hashAlgo=none"
	Query := QueryParamSeparator + NameParam + AndParamSeparator + VersionParam + AndParamSeparator + SignParam + AndParamSeparator + HashParam
	InputUrl := EndPoint + Query
	InputPayload := bytes.NewReader(data)

	fmt.Println("-> Sending hash to be signed by CipherTrust\n", fmt.Sprintf("%x\n", data))
	return NetworkHelperForSign(METHODPOST, InputUrl, InputPayload, OctetStreamContentType, AllTypeAccept)
}

func (c *clientApi) CreateKeyVersion(keyId string) (*CipherTrustCryptoKey, error) {
	EndPoint := CTMSERVICE + "/api/v1/vault/keys2/" + keyId + "/versions/"
	key, err := NetworkHelperForCreateKeyVersion(METHODPOST, EndPoint)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return key, nil
}

// To update the label
// name: Represent the name of the alias
// keyId: Represent the id of the key
// oldLabel: Represent the old label of the key
// label: Represent the new label of the key
// Returns a key otherwise error
func (c *clientApi) UpdateKeyLabel(name string, keyId string, oldLabel map[string]string, labels map[string]string) (*Key, error) {

	DeleteAlias(keyId, oldLabel)
	EndPoint := CTMSERVICE + "/api/v1/vault/keys2/" + keyId

	InputPayload := strings.NewReader(`{ "aliases": [{` + "" + `
			"alias":` + "\"" + keyId + "\"" + `,` + `
			"type": "string" }  ],` + `
		"labels": {` + "" + `
			  "spire-active": ` + "\"" + labels["spire-active"] + "\"" + `,` + `
			  "spire-server-id":` + "\"" + labels["spire-server-id"] + "\"" + `,` + `
			  "spire-server-td":` + "\"" + labels["spire-server-td"] + "\"" + `` + `
		}  }`)

	return NetworkHelperForUpdateKeyLabel(METHODPATCH, EndPoint, InputPayload, JsonType, JsonType)

}

// To update the label, we need to remove the existing alias
// keyId: Represent the id of the key
// label: Represent the label of the key
// Returns a key otherwise error
func DeleteAlias(keyId string, labels map[string]string) (*Key, error) {

	EndPoint := CTMSERVICE + "/api/v1/vault/keys2/" + keyId
	InputPayload := strings.NewReader(`{"aliases": [{` + "" + `	
				"index": 0}  ],` + `
		"labels": {` + "" + `
		"spire-active": ` + "\"" + labels["spire-active"] + "\"" + `,` + `
		"spire-server-id":` + "\"" + labels["spire-server-id"] + "\"" + `,` + `
		"spire-server-td":` + "\"" + labels["spire-server-td"] + "\"" + `` + `
  }  }`)

	return NetworkHelperForUpdateKeyLabel(METHODPATCH, EndPoint, InputPayload, JsonType, JsonType)

}

func (c *clientApi) GetPubKey(keyId string) (*CipherTrustCryptoKey, error) {
	EndPoint := CTMSERVICE + "/api/v1/vault/keys2/" + keyId

	return NetworkHelperForGetKey(METHODGET, EndPoint, JsonType)
}

func (c *clientApi) ListCrytoKeyVersions(key_id string, state string) (*CipherTrustCryptoKeysList, error) {
	EndPoint := CTMSERVICE + "/api/v1/vault/keys2/" + key_id

	return NetworkHelperForListKeyVersions(METHODGET, EndPoint, TextTypeAccept)

}

func (c *clientApi) DestroyCryptoKeyVersion( /*name, id, version*/ ) (*CipherTrustCryptoKeyVersion, error) {
	//TODO Optional
	return &CipherTrustCryptoKeyVersion{}, nil
}

func (c *clientApi) GetCryptoKeyVersion( /*name, id*/ ) (*CipherTrustCryptoKeyVersion, error) {
	// TODO Optional
	return &CipherTrustCryptoKeyVersion{}, nil
}
