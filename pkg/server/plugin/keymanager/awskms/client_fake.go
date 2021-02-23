package awskms

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type kmsClientFake struct {
	t *testing.T

	expectedCreateKeyInput *kms.CreateKeyInput
	createKeyOutput        *kms.CreateKeyOutput
	createKeyErr           error

	expectedDescribeKeyInput *kms.DescribeKeyInput
	describeKeyOutput        *kms.DescribeKeyOutput
	describeKeyErr           error

	expectedGetPublicKeyInput *kms.GetPublicKeyInput
	getPublicKeyOutput        *kms.GetPublicKeyOutput
	getPublicKeyErr           error

	expectedListAliasesInput *kms.ListAliasesInput
	listAliasesOutput        *kms.ListAliasesOutput
	listAliasesErr           error

	expectedListKeysInput *kms.ListKeysInput
	listKeysOutput        *kms.ListKeysOutput
	listKeysErr           error

	expectedScheduleKeyDeletionInput *kms.ScheduleKeyDeletionInput
	scheduleKeyDeletionOutput        *kms.ScheduleKeyDeletionOutput
	scheduleKeyDeletionErr           error

	expectedSignInput *kms.SignInput
	signOutput        *kms.SignOutput
	signErr           error
}

func (k *kmsClientFake) CreateKey(ctx context.Context, input *kms.CreateKeyInput, opts ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	if k.createKeyErr != nil {
		return nil, k.createKeyErr
	}
	return k.createKeyOutput, nil
}

func (k *kmsClientFake) DescribeKey(ctx context.Context, input *kms.DescribeKeyInput, opts ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if k.describeKeyErr != nil {
		return nil, k.describeKeyErr
	}

	return k.describeKeyOutput, nil
}

func (k *kmsClientFake) GetPublicKey(ctx context.Context, input *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if k.getPublicKeyErr != nil {
		return nil, k.getPublicKeyErr
	}

	return k.getPublicKeyOutput, nil
}

func (k *kmsClientFake) ListKeys(ctx context.Context, input *kms.ListKeysInput, opts ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	if k.listKeysErr != nil {
		return nil, k.listKeysErr
	}

	return k.listKeysOutput, nil
}

func (k *kmsClientFake) ListAliases(ctw context.Context, input *kms.ListAliasesInput, opts ...func(*kms.Options)) (*kms.ListAliasesOutput, error) {
	if k.listAliasesErr != nil {
		return nil, k.listAliasesErr
	}

	return k.listAliasesOutput, nil
}

func (k *kmsClientFake) ScheduleKeyDeletion(ctx context.Context, input *kms.ScheduleKeyDeletionInput, opts ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error) {
	if k.scheduleKeyDeletionErr != nil {
		return nil, k.scheduleKeyDeletionErr
	}

	return k.scheduleKeyDeletionOutput, nil
}

func (k *kmsClientFake) Sign(ctx context.Context, input *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error) {
	if k.signErr != nil {
		return nil, k.signErr
	}

	return k.signOutput, nil
}

func (k *kmsClientFake) CreateAlias(ctx context.Context, input *kms.CreateAliasInput, opts ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
	return nil, nil
}

func (k *kmsClientFake) UpdateAlias(ctw context.Context, input *kms.UpdateAliasInput, opts ...func(*kms.Options)) (*kms.UpdateAliasOutput, error) {
	return nil, nil
}
