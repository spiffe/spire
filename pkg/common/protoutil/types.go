package protoutil

import (
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/proto/spire/types"
)

// StrToSPIFFEID converts a SPIFFE ID from the given string into a *types.SPIFFEID
func StrToSPIFFEID(id string) (*types.SPIFFEID, error) {
	idType, err := spiffeid.FromString(id)
	if err != nil {
		return nil, err
	}
	return &types.SPIFFEID{
		TrustDomain: idType.TrustDomain().String(),
		Path:        idType.Path(),
	}, nil
}

// SPIFFEIDToStr converts a SPIFFE ID from the given *types.SPIFFEID to string
func SPIFFEIDToStr(id *types.SPIFFEID) string {
	return fmt.Sprintf("spiffe://%s%s", id.TrustDomain, id.Path)
}
