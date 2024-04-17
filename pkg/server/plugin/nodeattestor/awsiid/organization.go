package awsiid

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
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
	orgDefaultAccRegion      = "us-west-2"
)

var (
	orgAccountDefaultListDuration, _ = time.ParseDuration(orgAccountDefaultListTTL)
	orgAccountMinTTL, _              = time.ParseDuration(orgAccountMinListTTL)
)

type orgValidationConfig struct {
	AccountID      string `hcl:"management_account_id"`
	AccountRole    string `hcl:"assume_org_role"`
	AccountRegion  string `hcl:"management_account_region"`
	AccountListTTL string `hcl:"org_account_map_ttl"`
}

type orgValidator struct {
	orgAccountList              map[string]any
	orgAccountListValidDuration time.Time
	orgConfig                   *orgValidationConfig
	mutex                       sync.RWMutex
	// orgAccountListCacheTTL holds the cache ttl from configuration; otherwise, it will be set to the default value.
	orgAccountListCacheTTL time.Duration
	log                    hclog.Logger
	// retries fix number of retries before ttl is expired.
	retries int
	// require for testing
	clk clock.Clock
}

func newOrganizationValidationBase(config *orgValidationConfig) *orgValidator {
	client := &orgValidator{
		orgAccountList: make(map[string]any),
		orgConfig:      config,
		retries:        orgAccountRetries,
		clk:            clock.New(),
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
		o.retries--
	}

	return o.retries
}

func (o *orgValidator) configure(config *orgValidationConfig) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	o.orgConfig = config

	// While doing configuration invalidate the map so we dont keep using old one.
	o.orgAccountList = make(map[string]any)
	o.retries = orgAccountRetries

	t, err := time.ParseDuration(config.AccountListTTL)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "issue while parsing ttl for organization, while configuring orgnization validation: %v", err)
	}

	o.orgAccountListCacheTTL = t

	return nil
}

func (o *orgValidator) setLogger(log hclog.Logger) {
	o.log = log
}

// IsMemberAccount method checks if the Account ID attached on the node is part of the organisation.
// If it part of the organisation then validation should be succesfull if not attestation should fail, on enabling this verification method.
// This could be alternative for not explicitly maintaining allowed list of account ids.
// Method pulls the list of accounts from organization and caches it for certain time, cache time can be configured.
func (o *orgValidator) IsMemberAccount(ctx context.Context, orgClient organizations.ListAccountsAPIClient, accountIDOfNode string) (bool, error) {
	reValidatedCache, err := o.validateCache(ctx, orgClient)
	if err != nil {
		return false, err
	}

	accountIsmemberOfOrg, err := o.lookupCache(ctx, orgClient, accountIDOfNode, reValidatedCache)
	if err != nil {
		return false, err
	}

	return accountIsmemberOfOrg, nil
}

// validateCache validates cache and refresh if its stale
func (o *orgValidator) validateCache(ctx context.Context, orgClient organizations.ListAccountsAPIClient) (bool, error) {
	isStale := o.checkIfOrgAccountListIsStale()
	if !isStale {
		return false, nil
	}

	// cache is stale, reload the account map
	_, err := o.reloadAccountList(ctx, orgClient, false)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (o *orgValidator) lookupCache(ctx context.Context, orgClient organizations.ListAccountsAPIClient, accountIDOfNode string, reValidatedCache bool) (bool, error) {
	o.mutex.RLock()
	orgAccountList := o.orgAccountList
	o.mutex.RUnlock()

	_, accoutIsmemberOfOrg := orgAccountList[accountIDOfNode]

	// Retry if it doesn't exist in cache and cache was not revalidated
	if !accoutIsmemberOfOrg && !reValidatedCache {
		orgAccountList, err := o.refreshCache(ctx, orgClient)
		if err != nil {
			o.log.Error("Failed to refesh cache, while validating account id: %v", accountIDOfNode, "error", err.Error())
			return false, err
		}
		_, accoutIsmemberOfOrg = orgAccountList[accountIDOfNode]
	}

	return accoutIsmemberOfOrg, nil
}

// refreshCache refreshes list with new cache if cache miss happens and check if element exist
func (o *orgValidator) refreshCache(ctx context.Context, orgClient organizations.ListAccountsAPIClient) (map[string]any, error) {
	remTries := o.getRetries()

	orgAccountList := make(map[string]any)
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

// checkIfOrgAccountListIsStale checks if the cached org account list is stale.
func (o *orgValidator) checkIfOrgAccountListIsStale() bool {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	// Map is empty that means this is first time plugin is being initialised
	if len(o.orgAccountList) == 0 {
		return true
	}

	return o.checkIfTTLIsExpired(o.orgAccountListValidDuration)
}

// reloadAccountList gets the list of accounts belonging to organization and catch them
func (o *orgValidator) reloadAccountList(ctx context.Context, orgClient organizations.ListAccountsAPIClient, catchBurst bool) (map[string]any, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	// Make sure: we are not doing cache burst and account map is not updated recently from different go routine.
	if !catchBurst && len(o.orgAccountList) != 0 && !o.checkIfTTLIsExpired(o.orgAccountListValidDuration) {
		return o.orgAccountList, nil
	}

	// Avoid if other thread has already updated the map
	if catchBurst && o.retries == 0 {
		return o.orgAccountList, nil
	}

	// Get the list of accounts
	listAccountsOp, err := orgClient.ListAccounts(ctx, &organizations.ListAccountsInput{})
	if err != nil {
		return nil, fmt.Errorf("issue while getting list of accounts: %w", err)
	}

	// Build new org accounts list
	orgAccountsMap := make(map[string]any)

	// Update the org account list cache with ACTIVE accounts & handle pagination
	for {
		for _, acc := range listAccountsOp.Accounts {
			if acc.Status == types.AccountStatusActive {
				accID := *acc.Id
				orgAccountsMap[accID] = struct{}{}
			}
		}

		if listAccountsOp.NextToken == nil {
			break
		}

		listAccountsOp, err = orgClient.ListAccounts(ctx, &organizations.ListAccountsInput{
			NextToken: listAccountsOp.NextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("issue while getting list of accounts in pagination: %w", err)
		}
	}

	// Update timestamp, if it was not invoked as part of cache miss.
	if !catchBurst {
		o.orgAccountListValidDuration = o.clk.Now().UTC().Add(o.orgAccountListCacheTTL)
		// Also reset the retries
		o.retries = orgAccountRetries
	}

	// Overwrite the cache/list
	o.orgAccountList = orgAccountsMap

	return o.orgAccountList, nil
}

// checkIFTTLIsExpire check if the creation time is pass defined ttl
func (o *orgValidator) checkIfTTLIsExpired(ttl time.Time) bool {
	currTimeStamp := o.clk.Now().UTC()
	return currTimeStamp.After(ttl)
}
