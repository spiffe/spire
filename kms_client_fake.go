package kms

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/stretchr/testify/require"
)

const (
	signVerifyKeyUsage string = "SIGN_VERIFY"
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

func (k *kmsClientFake) CreateKeyWithContext(ctx aws.Context, input *kms.CreateKeyInput, opts ...request.Option) (*kms.CreateKeyOutput, error) {
	require.Equal(k.t, k.expectedCreateKeyInput, input)
	if k.createKeyErr != nil {
		return nil, k.createKeyErr
	}
	return k.createKeyOutput, nil
}

func (k *kmsClientFake) DescribeKeyWithContext(ctx aws.Context, input *kms.DescribeKeyInput, opts ...request.Option) (*kms.DescribeKeyOutput, error) {
	require.Equal(k.t, k.expectedDescribeKeyInput, input)
	if k.describeKeyErr != nil {
		return nil, k.describeKeyErr
	}

	return k.describeKeyOutput, nil
}

func (k *kmsClientFake) GetPublicKeyWithContext(ctx aws.Context, input *kms.GetPublicKeyInput, opts ...request.Option) (*kms.GetPublicKeyOutput, error) {
	require.Equal(k.t, k.expectedGetPublicKeyInput, input)
	if k.getPublicKeyErr != nil {
		return nil, k.getPublicKeyErr
	}

	return k.getPublicKeyOutput, nil
}

func (k *kmsClientFake) ListKeysWithContext(ctx aws.Context, input *kms.ListKeysInput, opts ...request.Option) (*kms.ListKeysOutput, error) {
	require.Equal(k.t, k.expectedListKeysInput, input)
	if k.listKeysErr != nil {
		return nil, k.listKeysErr
	}

	return k.listKeysOutput, nil
}

func (k *kmsClientFake) ListAliasesWithContext(ctw aws.Context, input *kms.ListAliasesInput, opts ...request.Option) (*kms.ListAliasesOutput, error) {
	require.Equal(k.t, k.expectedListAliasesInput, input)
	if k.listAliasesErr != nil {
		return nil, k.listAliasesErr
	}

	return k.listAliasesOutput, nil
}

func (k *kmsClientFake) ScheduleKeyDeletionWithContext(ctx aws.Context, input *kms.ScheduleKeyDeletionInput, opts ...request.Option) (*kms.ScheduleKeyDeletionOutput, error) {
	require.Equal(k.t, k.expectedScheduleKeyDeletionInput, input)
	if k.scheduleKeyDeletionErr != nil {
		return nil, k.scheduleKeyDeletionErr
	}

	return k.scheduleKeyDeletionOutput, nil
}

func (k *kmsClientFake) SignWithContext(ctx aws.Context, input *kms.SignInput, opts ...request.Option) (*kms.SignOutput, error) {
	require.Equal(k.t, k.expectedSignInput, input)
	if k.signErr != nil {
		return nil, k.signErr
	}

	return k.signOutput, nil
}

func (k *kmsClientFake) CreateAliasWithContext(ctx aws.Context, input *kms.CreateAliasInput, opts ...request.Option) (*kms.CreateAliasOutput, error) {
	return nil, nil
}

func (k *kmsClientFake) UpdateAliasWithContext(ctw aws.Context, input *kms.UpdateAliasInput, opts ...request.Option) (*kms.UpdateAliasOutput, error) {
	return nil, nil
}
