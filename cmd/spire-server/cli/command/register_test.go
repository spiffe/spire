package command

import (
	"fmt"
	"testing"

	"math/rand"

	"golang.org/x/net/context"

	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/mock/server/proto"
	"github.com/stretchr/testify/assert"
)

// TODO: Test additional scenarios

func TestRegisterCommand_DataOK(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockClient := mocks.NewMockRegistrationClient(mockCtrl)
	ctx := context.Background()

	entry1 := &common.RegistrationEntry{
		Selectors: []*common.Selector{
			&common.Selector{
				Type:  "unix",
				Value: "uid:1111",
			},
		},
		SpiffeId: "spiffe://example.org/Blog",
		ParentId: "spiffe://example.org/spiffe/node-id/TokenBlog",
		Ttl:      200,
	}
	retID1 := &registration.RegistrationEntryID{
		Id: fmt.Sprint(rand.Int()),
	}
	mockClient.EXPECT().CreateEntry(
		ctx,
		entry1,
	).Return(retID1, nil)
	mockClient.EXPECT().FetchEntry(ctx, retID1).Return(entry1, nil)

	entry2 := &common.RegistrationEntry{
		Selectors: []*common.Selector{
			&common.Selector{
				Type:  "unix",
				Value: "uid:1111",
			},
		},
		SpiffeId: "spiffe://example.org/Database",
		ParentId: "spiffe://example.org/spiffe/node-id/TokenDatabase",
		Ttl:      200,
	}
	retID2 := &registration.RegistrationEntryID{
		Id: fmt.Sprint(rand.Int()),
	}
	mockClient.EXPECT().CreateEntry(
		ctx,
		entry2,
	).Return(retID2, nil)
	mockClient.EXPECT().FetchEntry(ctx, retID2).Return(entry2, nil)

	regcmd := &RegisterCommand{
		Client: mockClient,
	}
	retval := regcmd.Run([]string{"test_data/registration.json"})
	assert.Equal(t, retval, 0)
}
