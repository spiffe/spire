package awsiid

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	orgAccountID             = "org_account_id"
	orgAccountRole           = "org_account_role"
	orgAccRegion             = "org_account_region"  // required for cache key
	orgAccountStatus         = "ACTIVE"              // Only allow node account id's with status ACTIVE
	orgAccountListTTL        = "org_account_map_ttl" // Cache the list of account for specific time, if not sent default will be used.
	orgAccountDefaultListTTL = "3h"                  // pull account list after 3 hrs
	orgAccountMinListTTL     = "1h"                  // Minimum TTL configuration to pull the org account list
)

type orgValidationConfig struct {
	AccountID      string `hcl:"org_account_id"`
	AccountRole    string `hcl:"org_account_role"`
	AccountRegion  string `hcl:"org_account_region"`
	AccountListTTL string `hcl:"org_account_map_ttl"`
}

type organizationValidation struct {
	orgListAccountMap             map[string]bool
	orgListAccountMapCreationTime time.Time
	orgConfig                     *orgValidationConfig
	mutex                         sync.RWMutex
	orgAccountListCacheTTL        time.Duration // set from configuration else will be set to default
	log                           hclog.Logger
}

func newOrganizationValidationBase(config *orgValidationConfig) *organizationValidation {
	client := &organizationValidation{
		orgListAccountMap: make(map[string]bool),
		orgConfig:         config,
	}

	return client
}

func (o *organizationValidation) configure(config *orgValidationConfig) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	o.orgConfig = config
	// While doing configuration invalidate the map so we dont keep using old one.
	o.orgListAccountMap = make(map[string]bool)

	t, err := time.ParseDuration(config.AccountListTTL)
	if err != nil {
		return status.Errorf(codes.Internal, "issue while parsing ttl for organization, while configuring orgnization validation: %v", err)
	}

	o.orgAccountListCacheTTL = t

	return nil
}

func (o *organizationValidation) setLogger(log hclog.Logger) {
	o.log = log
}

// This verification method checks if the Account ID attached on the node is part of the organisation.
// If it part of the organisation then validation should be succesfull if not attestation should fail, on enabling this verification method.
// This could be alternative for not explictly maintaing allowed list of account ids.
// Method pulls the list of accounts from organization and caches it for certain time, cache time can be configured.
func (o *organizationValidation) ValidateAccountBelongstoOrg(ctx context.Context, orgClient organizations.ListAccountsAPIClient, accoundIDofNode string) (bool, error) {

	orgAccountList, isStale, err := o.checkIfOrgAccountListIsStale(ctx)
	if err != nil {
		return false, err
	}
	// refresh the account map
	if isStale {
		orgAccountList, err = o.fetchAccountsListFromOrg(ctx, orgClient)
		if err != nil {
			return false, err
		}
	}

	// Check if account contains in organization list
	_, exist := orgAccountList[accoundIDofNode]
	if !exist {
		return false, nil
	}

	return true, nil
}

// Check if the org account list is stale.
func (o *organizationValidation) checkIfOrgAccountListIsStale(ctx context.Context) (map[string]bool, bool, error) {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	// Map is empty that means this is first time plugin is being initialised
	if len(o.orgListAccountMap) == 0 {
		return nil, true, nil
	}

	// Get the timestamp from config
	existingTimestamp := o.orgListAccountMapCreationTime

	currTimeStamp := time.Now().UTC()

	// Check diff of timestamp of org acc map & current time if its more than ttl, refresh the list
	if currTimeStamp.Sub(existingTimestamp) >= time.Duration(o.orgAccountListCacheTTL) {
		return nil, true, nil
	}

	return o.orgListAccountMap, false, nil
}

// Get the list of accounts belonging to organization and catch them
func (o *organizationValidation) fetchAccountsListFromOrg(ctx context.Context, orgClient organizations.ListAccountsAPIClient) (map[string]bool, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	// Make sure map is not updated from different go routine. This will make sure we dont make extra calls
	if len(o.orgListAccountMap) != 0 && time.Now().UTC().Sub(o.orgListAccountMapCreationTime) <= time.Duration(o.orgAccountListCacheTTL) {
		return o.orgListAccountMap, nil
	}

	// Get the list of accounts
	listAccountsOp, err := orgClient.ListAccounts(ctx, &organizations.ListAccountsInput{})
	if err != nil {
		return nil, fmt.Errorf("issue while getting list of accounts: %v", err)
	}

	//Build new org accounts list
	orgAccountsMap := make(map[string]bool)

	// Update the org account list cache with ACTIVE accounts & handle pagination
	for {

		for _, acc := range listAccountsOp.Accounts {
			if acc.Status == types.AccountStatusActive {
				accId := *acc.Id
				orgAccountsMap[accId] = true
			}
		}

		if listAccountsOp.NextToken == nil {
			break
		}

		listAccountsOp, err = orgClient.ListAccounts(ctx, &organizations.ListAccountsInput{
			NextToken: listAccountsOp.NextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("issue while getting list of accounts in pagination: %v", err)
		}
	}

	// Add timestamp to make sure we can validate its expiry
	t := time.Now().UTC()
	o.orgListAccountMapCreationTime = t

	// Overwrite the cache/list
	o.orgListAccountMap = orgAccountsMap

	return o.orgListAccountMap, nil
}

func validateOrganizationConfig(config *IIDAttestorConfig) error {
	checkAccid := config.ValidateOrgAccountID.AccountID
	checkAccRole := config.ValidateOrgAccountID.AccountRole
	checkAccRegion := config.ValidateOrgAccountID.AccountRegion

	if len(checkAccid) == 0 || len(checkAccRole) == 0 || len(checkAccRegion) == 0 {
		return status.Errorf(codes.InvalidArgument, "make sure %v, %v & %v are present inside block or remove the block : %v for feature node attestation using account id verification", orgAccountID, orgAccountRole, orgAccRegion, "account_ids_belong_to_org_validation")
	}

	// check TTL if specified
	checkTTL := config.ValidateOrgAccountID.AccountListTTL
	var ttl time.Duration

	if len(checkTTL) > 0 {
		t, err := time.ParseDuration(checkTTL)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "make sure %v if configured, should be in hours and is suffix with required `h` for time duration in hour ex. 1h. or remove the : %v, in the block : %v. Default TTL will be : %v,  for feature node attestation using account id verification", orgAccountListTTL, orgAccountListTTL, "account_ids_belong_to_org_validation", orgAccountDefaultListTTL)
		}

		minTTL, err := time.ParseDuration(orgAccountMinListTTL)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "issue parsing default minimum ttl: %v, err : %v", orgAccountMinListTTL, err)
		}

		if t.Hours() < minTTL.Hours() {
			return status.Errorf(codes.InvalidArgument, "make sure %v if configured, should be more than >= %v. or remove the : %v, in the block : %v. Default TTL will be : %v,  for feature node attestation using account id verification", orgAccountListTTL, orgAccountMinListTTL, orgAccountListTTL, "account_ids_belong_to_org_validation", orgAccountDefaultListTTL)
		}

		ttl = t

	} else {
		defaultTTL, err := time.ParseDuration(orgAccountDefaultListTTL)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "issue parsing default ttl: %v, err : %v", orgAccountDefaultListTTL, err)
		}
		ttl = defaultTTL
	}

	// Assign default ttl if ttl doesnt exist.
	config.ValidateOrgAccountID.AccountListTTL = ttl.String()

	return nil
}
