package awskms

import (
	"context"
	"errors"
	"path"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	rgtatypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/aws/smithy-go"
	"github.com/hashicorp/go-hclog"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type keyFetcher struct {
	log           hclog.Logger
	kmsClient     kmsClient
	taggingClient taggingClient
	serverID      string
	trustDomain   string
}

// fetchKeyEntriesViaAlias uses the legacy alias-based discovery method.
// This approach lists all aliases and filters by the SPIRE prefix pattern.
func (kf *keyFetcher) fetchKeyEntriesViaAlias(ctx context.Context) ([]*keyEntry, error) {
	var keyEntries []*keyEntry
	var keyEntriesMutex sync.Mutex
	paginator := kms.NewListAliasesPaginator(kf.kmsClient, &kms.ListAliasesInput{Limit: aws.Int32(100)})
	g, ctx := errgroup.WithContext(ctx)

	for {
		aliasesResp, err := paginator.NextPage(ctx)
		switch {
		case err != nil:
			return nil, status.Errorf(codes.Internal, "failed to fetch aliases: %v", err)
		case aliasesResp == nil:
			return nil, status.Errorf(codes.Internal, "failed to fetch aliases: nil response")
		}

		kf.log.Debug("Found aliases", "num_aliases", len(aliasesResp.Aliases))

		for _, alias := range aliasesResp.Aliases {
			// Ensure the alias has a name. This check is purely defensive
			// since aliases should always have a name.
			if alias.AliasName == nil {
				continue
			}

			spireKeyID, ok := kf.spireKeyIDFromAlias(*alias.AliasName)
			// ignore aliases/keys not belonging to this server
			if !ok {
				continue
			}

			// The following checks are purely defensive, but we want to ensure
			// we don't try and handle an alias with a malformed shape.
			switch {
			case alias.AliasArn == nil:
				return nil, status.Errorf(codes.Internal, "failed to fetch aliases: found SPIRE alias without arn: name=%q", *alias.AliasName)
			case alias.TargetKeyId == nil:
				// this means something external to the plugin created the alias, without associating it to a key.
				// it should never happen with CMKs.
				return nil, status.Errorf(codes.FailedPrecondition, "failed to fetch aliases: found SPIRE alias without key: name=%q arn=%q", *alias.AliasName, *alias.AliasArn)
			}

			a := alias
			// trigger a goroutine to get the details of the key
			g.Go(func() error {
				entry, err := kf.fetchKeyEntryDetails(ctx, a, spireKeyID)
				if err != nil {
					return err
				}

				keyEntriesMutex.Lock()
				keyEntries = append(keyEntries, entry)
				keyEntriesMutex.Unlock()
				return nil
			})
		}

		if !paginator.HasMorePages() {
			break
		}
	}

	// wait for all the detail gathering routines to finish
	if err := g.Wait(); err != nil {
		statusErr := status.Convert(err)
		return nil, status.Errorf(statusErr.Code(), "failed to fetch aliases: %v", statusErr.Message())
	}

	return keyEntries, nil
}

func (kf *keyFetcher) fetchKeyEntryDetails(ctx context.Context, alias types.AliasListEntry, spireKeyID string) (*keyEntry, error) {
	describeResp, err := kf.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: alias.AliasArn})
	switch {
	case err != nil:
		return nil, status.Errorf(codes.Internal, "failed to describe key: %v", err)
	case describeResp == nil || describeResp.KeyMetadata == nil:
		return nil, status.Error(codes.Internal, "malformed describe key response")
	case describeResp.KeyMetadata.Arn == nil:
		return nil, status.Errorf(codes.Internal, "found SPIRE alias without key arn: %q", *alias.AliasArn)
	case !describeResp.KeyMetadata.Enabled:
		// this means something external to the plugin, deleted or disabled the key without removing the alias
		// returning an error provides the opportunity or reverting this in KMS
		return nil, status.Errorf(codes.FailedPrecondition, "found disabled SPIRE key: %q, alias: %q", *describeResp.KeyMetadata.Arn, *alias.AliasArn)
	}

	keyType, ok := keyTypeFromKeySpec(describeResp.KeyMetadata.KeySpec)
	if !ok {
		return nil, status.Errorf(codes.Internal, "unsupported key spec: %v", describeResp.KeyMetadata.KeySpec)
	}

	publicKeyResp, err := kf.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: alias.AliasArn})
	switch {
	case err != nil:
		return nil, status.Errorf(codes.Internal, "failed to get public key: %v", err)
	case publicKeyResp == nil || publicKeyResp.PublicKey == nil || len(publicKeyResp.PublicKey) == 0:
		return nil, status.Error(codes.Internal, "malformed get public key response")
	}

	return &keyEntry{
		Arn:       *describeResp.KeyMetadata.Arn,
		AliasName: *alias.AliasName,
		PublicKey: &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    publicKeyResp.PublicKey,
			Fingerprint: makeFingerprint(publicKeyResp.PublicKey),
		},
	}, nil
}

func (kf *keyFetcher) spireKeyIDFromAlias(aliasName string) (string, bool) {
	trustDomain := sanitizeTrustDomain(kf.trustDomain)
	prefix := path.Join(aliasPrefix, trustDomain, kf.serverID) + "/"
	trimmed := strings.TrimPrefix(aliasName, prefix)
	if trimmed == aliasName {
		return "", false
	}
	return decodeKeyID(trimmed), true
}

// fetchKeyEntriesViaTag uses AWS Resource Groups Tagging API for efficient key discovery.
// This approach filters keys by SPIRE-specific tags similar to how GCP KMS uses labels.
// Keys are filtered by: trust domain, server ID, and active status.
func (kf *keyFetcher) fetchKeyEntriesViaTag(ctx context.Context) ([]*keyEntry, error) {
	var keyEntries []*keyEntry
	var keyEntriesMutex sync.Mutex
	g, ctx := errgroup.WithContext(ctx)

	// Build tag filters to find only keys belonging to this server
	// Unlike GCP, AWS supports dots in tag values, so we use the trust domain directly
	tagFilters := []rgtatypes.TagFilter{
		{
			Key:    aws.String(tagKeyServerTD),
			Values: []string{kf.trustDomain},
		},
		{
			Key:    aws.String(tagKeyServerID),
			Values: []string{kf.serverID},
		},
		{
			Key:    aws.String(tagKeyActive),
			Values: []string{"true"},
		},
	}

	// Use pagination to handle large numbers of keys
	paginator := resourcegroupstaggingapi.NewGetResourcesPaginator(kf.taggingClient, &resourcegroupstaggingapi.GetResourcesInput{
		ResourceTypeFilters: []string{"kms:key"},
		TagFilters:          tagFilters,
	})

	for {
		resourcesResp, err := paginator.NextPage(ctx)
		switch {
		case err != nil:
			if permErr := tagGetResourcesPermissionError(err); permErr != nil {
				return nil, permErr
			}
			return nil, status.Errorf(codes.Internal, "failed to fetch keys by tags: %v", err)
		case resourcesResp == nil:
			return nil, status.Error(codes.Internal, "failed to fetch keys by tags: nil response")
		}

		kf.log.Debug("Found keys with SPIRE tags", "num_keys", len(resourcesResp.ResourceTagMappingList))

		for _, resource := range resourcesResp.ResourceTagMappingList {
			if resource.ResourceARN == nil {
				continue
			}

			keyArn := *resource.ResourceARN

			// Extract SPIRE key ID from tags
			spireKeyID, ok := kf.spireKeyIDFromTags(resource.Tags)
			if !ok {
				kf.log.Warn("Could not get SPIRE key ID from tags", "key_arn", keyArn)
				continue
			}

			// Trigger a goroutine to get the details of the key
			g.Go(func() error {
				entry, err := kf.fetchKeyEntryDetailsFromArn(ctx, keyArn, spireKeyID)
				if err != nil {
					return err
				}
				if entry == nil {
					return nil
				}

				keyEntriesMutex.Lock()
				keyEntries = append(keyEntries, entry)
				keyEntriesMutex.Unlock()
				return nil
			})
		}

		if !paginator.HasMorePages() {
			break
		}
	}

	// Wait for all the detail gathering routines to finish
	if err := g.Wait(); err != nil {
		statusErr := status.Convert(err)
		return nil, status.Errorf(statusErr.Code(), "failed to fetch key entries: %v", statusErr.Message())
	}

	return keyEntries, nil
}

// fetchKeyEntryDetailsFromArn retrieves key details using a key ARN directly.
// This is used for tag-based discovery where we get the ARN from the tagging API.
func (kf *keyFetcher) fetchKeyEntryDetailsFromArn(ctx context.Context, keyArn string, spireKeyID string) (*keyEntry, error) {
	describeResp, err := kf.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &keyArn})
	switch {
	case err != nil:
		return nil, status.Errorf(codes.Internal, "failed to describe key: %v", err)
	case describeResp == nil || describeResp.KeyMetadata == nil:
		return nil, status.Error(codes.Internal, "malformed describe key response")
	case describeResp.KeyMetadata.Arn == nil:
		return nil, status.Errorf(codes.Internal, "found SPIRE key without arn: %q", keyArn)
	case !describeResp.KeyMetadata.Enabled:
		// Key is disabled or pending deletion. This can happen when a key
		// was scheduled for deletion by the alias-based disposal path,
		// which does not clear SPIRE tags. Skip the key gracefully.
		kf.log.Warn("Skipping disabled SPIRE key found via tags", keyArnTag, keyArn)
		return nil, nil
	}

	keyType, ok := keyTypeFromKeySpec(describeResp.KeyMetadata.KeySpec)
	if !ok {
		return nil, status.Errorf(codes.Internal, "unsupported key spec: %v", describeResp.KeyMetadata.KeySpec)
	}

	publicKeyResp, err := kf.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &keyArn})
	switch {
	case err != nil:
		return nil, status.Errorf(codes.Internal, "failed to get public key: %v", err)
	case publicKeyResp == nil || publicKeyResp.PublicKey == nil || len(publicKeyResp.PublicKey) == 0:
		return nil, status.Error(codes.Internal, "malformed get public key response")
	}

	// Build the expected alias name for this key. Even though we're using tag-based discovery,
	// aliases are still created for all keys (for human-readable names in AWS console).
	trustDomain := sanitizeTrustDomain(kf.trustDomain)
	aliasName := path.Join(aliasPrefix, trustDomain, kf.serverID, encodeKeyID(spireKeyID))

	return &keyEntry{
		Arn:       *describeResp.KeyMetadata.Arn,
		AliasName: aliasName,
		PublicKey: &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    publicKeyResp.PublicKey,
			Fingerprint: makeFingerprint(publicKeyResp.PublicKey),
		},
	}, nil
}

// fetchKeyEntriesWithMigration performs tag-based discovery with automatic
// migration of pre-existing untagged keys. It fetches keys via both tags and
// aliases, then applies SPIRE tags to any alias-discovered keys that don't
// have them yet. This allows a transparent one-time migration from alias-based
// to tag-based discovery without any manual steps. lastUpdate is the
// spire-last-update tag value stamped on migrated keys so they are immediately
// eligible for staleness evaluation.
func (kf *keyFetcher) fetchKeyEntriesWithMigration(ctx context.Context, spireTags []types.Tag, lastUpdate string) ([]*keyEntry, error) {
	taggedEntries, err := kf.fetchKeyEntriesViaTag(ctx)
	if err != nil {
		return nil, err
	}

	// Also run alias-based discovery to catch pre-existing keys that were
	// created before tag-based discovery was enabled.
	aliasEntries, err := kf.fetchKeyEntriesViaAlias(ctx)
	if err != nil {
		return nil, err
	}

	taggedIDs := make(map[string]bool, len(taggedEntries))
	for _, e := range taggedEntries {
		taggedIDs[e.PublicKey.Id] = true
	}

	var migratedCount int
	for _, entry := range aliasEntries {
		if taggedIDs[entry.PublicKey.Id] {
			continue
		}

		kf.log.Info("Applying SPIRE tags to legacy key during migration to tag-based discovery",
			keyArnTag, entry.Arn)

		// Build a fresh slice to avoid mutating the shared spireTags backing array.
		tags := append(append([]types.Tag(nil), spireTags...),
			types.Tag{
				TagKey:   aws.String(tagKeySPIREKeyID),
				TagValue: aws.String(entry.PublicKey.Id),
			},
			types.Tag{
				TagKey:   aws.String(tagKeyLastUpdate),
				TagValue: aws.String(lastUpdate),
			},
		)
		if _, err := kf.kmsClient.TagResource(ctx, &kms.TagResourceInput{
			KeyId: &entry.Arn,
			Tags:  tags,
		}); err != nil {
			// Don't fail startup. The key is still usable and tagging will
			// be retried on the next server restart.
			kf.log.Warn("Failed to apply SPIRE tags to legacy key during migration; key will still be available",
				keyArnTag, entry.Arn, reasonTag, err)
		}

		migratedCount++
		taggedEntries = append(taggedEntries, entry)
	}

	if migratedCount > 0 {
		kf.log.Info("Tag-based key discovery migration finished",
			"migrated_keys", migratedCount, "total_keys", len(taggedEntries))
	} else {
		kf.log.Debug("No legacy keys required migration to tag-based discovery",
			"total_keys", len(taggedEntries))
	}

	return taggedEntries, nil
}

// spireKeyIDFromTags extracts the SPIRE key ID from a resource's tags.
func (kf *keyFetcher) spireKeyIDFromTags(tags []rgtatypes.Tag) (string, bool) {
	for _, tag := range tags {
		if tag.Key != nil && *tag.Key == tagKeySPIREKeyID && tag.Value != nil {
			return *tag.Value, true
		}
	}
	return "", false
}

// tagGetResourcesPermissionError returns an actionable error when err indicates
// the identity is not authorized to call tag:GetResources. Tag-based key
// discovery relies on the Resource Groups Tagging API, whose permissions are
// identity-based and cannot be granted through the KMS key policy. Returns nil
// when err is not an access-denied error.
func tagGetResourcesPermissionError(err error) error {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && apiErr.ErrorCode() == "AccessDeniedException" {
		return status.Errorf(codes.FailedPrecondition,
			"tag-based key discovery requires the \"tag:GetResources\" permission in an "+
				"identity-based IAM policy (it cannot be granted through the KMS key policy); "+
				"grant the permission or disable enable_tag_based_key_discovery: %v", err)
	}
	return nil
}
