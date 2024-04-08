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
	orgAccountID             = "management_account_id"
	orgAccountRole           = "assume_org_role"
	orgAccRegion             = "management_account_region" // required for cache key
	orgAccountStatus         = "ACTIVE"                    // Only allow node account id's with status ACTIVE
	orgAccountListTTL        = "org_account_map_ttl"       // Cache the list of account for specific time, if not sent default will be used.
	orgAccountDefaultListTTL = "3m"                        // pull account list after 3 minutes
	orgAccountMinListTTL     = "1m"                        // Minimum TTL configuration to pull the org account list
	orgAccountRetries        = 5
)

type orgValidationConfig struct {
	AccountID      string `hcl:"management_account_id"`
	AccountRole    string `hcl:"assume_org_role"`
	AccountRegion  string
	AccountListTTL string `hcl:"org_account_map_ttl"`
}

type orgValidator struct {
	orgListAccountMap             map[string]bool
	orgListAccountMapCreationTime time.Time
	orgConfig                     *orgValidationConfig
	mutex                         sync.RWMutex
        // orgAccountListCacheTTL holds the cache ttl from configuration; otherwise, it will be set to the default value.
	orgAccountListCacheTTL        time.Duration 
	log                           hclog.Logger
        // retries fix number of retries before ttl is expired.
	retries                       int
}

func newOrganizationValidationBase(config *orgValidationConfig) *orgValidator {
	client := &orgValidator{
		orgListAccountMap: make(map[string]bool),
		orgConfig:         config,
		retries:           orgAccountRetries,
	}

	return client
}

func (o *orgValidator) getRetries() int {
	o.mutex.RLock()
	defer o.mutex.RUnlock()
	return o.retries
}

func (o *orgValidator) decrRetries() int {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	if o.retries > 0 {
		o.retries -= 1
	}

	return o.retries
}

func (o *orgValidator) configure(config *orgValidationConfig) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	o.orgConfig = config
	// required for the way existing getClient function is designed
	o.orgConfig.AccountRegion = "us-west-2"

	// While doing configuration invalidate the map so we dont keep using old one.
	o.orgListAccountMap = make(map[string]bool)
	o.retries = orgAccountRetries

	t, err := time.ParseDuration(config.AccountListTTL)
	if err != nil {
		return status.Errorf(codes.Internal, "issue while parsing ttl for organization, while configuring orgnization validation: %v", err)
	}

	o.orgAccountListCacheTTL = t

	return nil
}

func (o *orgValidator) setLogger(log hclog.Logger) {
	o.log = log
}

// This verification method checks if the Account ID attached on the node is part of the organisation.
// If it part of the organisation then validation should be succesfull if not attestation should fail, on enabling this verification method.
// This could be alternative for not explictly maintaing allowed list of account ids.
// Method pulls the list of accounts from organization and caches it for certain time, cache time can be configured.
func (o *orgValidator) IsMemberAccount(ctx context.Context, orgClient organizations.ListAccountsAPIClient, accoundIDofNode string) (bool, error) {
	reValidatedcache, err := o.validateCache(ctx, orgClient)
	if err != nil {
		return false, err
	}

	accountIsmemberofOrg, err := o.lookupCache(ctx, orgClient, accoundIDofNode, reValidatedcache)
	if err != nil {
		return false, err
	}

	return accountIsmemberofOrg, nil
}

// validateCache validates cache and refresh if its stale
func (o *orgValidator) validateCache(ctx context.Context, orgClient organizations.ListAccountsAPIClient) (bool, error) {
	isStale, err := o.checkIfOrgAccountListIsStale(ctx)
	if err != nil {
		return isStale, err
	}

	// refresh the account map
	if isStale {
		_, err = o.reloadAccountList(ctx, orgClient, false)
		if err != nil {
			return isStale, err
		}
	}
	return isStale, nil
}

func (o *orgValidator) lookupCache(ctx context.Context, orgClient organizations.ListAccountsAPIClient, accoundIDofNode string, reValidatedcache bool) (bool, error) {
	o.mutex.RLock()
	orgAccountList := o.orgListAccountMap
	o.mutex.RUnlock()

	_, accoutIsmemberOfOrg := orgAccountList[accoundIDofNode]

	// Retry if it doesn't exist in cache and cache was not revalidated
	if !accoutIsmemberOfOrg && !reValidatedcache {
		orgAccountList, err := o.refreshCache(ctx, orgClient)
		if err != nil {
			return false, err
		}
		_, accoutIsmemberOfOrg = orgAccountList[accoundIDofNode]
	}

	return accoutIsmemberOfOrg, nil
}

// If cache miss happens, refresh list with new cache and check if element exist
func (o *orgValidator) refreshCache(ctx context.Context, orgClient organizations.ListAccountsAPIClient) (map[string]bool, error) {
	remTries := o.getRetries()

	orgAccountList := make(map[string]bool)
	if remTries <= 0 {
		return orgAccountList, nil
	}

	orgAccountList, err := o.reloadAccountList(ctx, orgClient, true)
	if err != nil {
		return nil, err
	}

	o.decrRetries()

	return orgAccountList, nil
}

// Check if the org account list is stale.
func (o *orgValidator) checkIfOrgAccountListIsStale(ctx context.Context) (bool, error) {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	// Map is empty that means this is first time plugin is being initialised
	if len(o.orgListAccountMap) == 0 {
		return true, nil
	}

	// Get the timestamp from config
	existingTimestamp := o.orgListAccountMapCreationTime

	currTimeStamp := time.Now().UTC()

	// Check diff of timestamp of org acc map & current time if its more than ttl, refresh the list
	if currTimeStamp.Sub(existingTimestamp) >= time.Duration(o.orgAccountListCacheTTL) {
		return true, nil
	}

	return false, nil
}

// reloadAccountList gets the list of accounts belonging to organization and catch them
func (o *orgValidator) reloadAccountList(ctx context.Context, orgClient organizations.ListAccountsAPIClient, catchBurst bool) (map[string]bool, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	// Make sure: map is not updated from different go routine.
	// * if we make this call before ttl expires, we are doing retry/catchburst that means we need to bypass this validation
	if !catchBurst && len(o.orgListAccountMap) != 0 && time.Now().UTC().Sub(o.orgListAccountMapCreationTime) <= time.Duration(o.orgAccountListCacheTTL) {
		return o.orgListAccountMap, nil
	}

	// Avoid if other thread has already updated the map
	if catchBurst && o.retries == 0 {
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

	// Update timestamp, if it was not invoked as part of cache miss.
	if !catchBurst {
		t := time.Now().UTC()
		o.orgListAccountMapCreationTime = t
		// Also reset the retries
		o.retries = orgAccountRetries
	}

	// Overwrite the cache/list
	o.orgListAccountMap = orgAccountsMap

	return o.orgListAccountMap, nil
}
