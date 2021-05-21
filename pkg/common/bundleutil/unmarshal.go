package bundleutil

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/zeebo/errs"
)

func Decode(trustDomain spiffeid.TrustDomain, r io.Reader) (*Bundle, error) {
	doc := new(bundleDoc)
	if err := json.NewDecoder(r).Decode(doc); err != nil {
		return nil, fmt.Errorf("failed to decode bundle: %w", err)
	}
	return unmarshal(trustDomain, doc)
}

func Unmarshal(trustDomain spiffeid.TrustDomain, data []byte) (*Bundle, error) {
	doc := new(bundleDoc)
	if err := json.Unmarshal(data, doc); err != nil {
		return nil, errs.Wrap(err)
	}
	return unmarshal(trustDomain, doc)
}

func unmarshal(trustDomain spiffeid.TrustDomain, doc *bundleDoc) (*Bundle, error) {
	bundle := New(trustDomain)
	bundle.SetRefreshHint(time.Second * time.Duration(doc.RefreshHint))

	for i, key := range doc.Keys {
		switch key.Use {
		case x509SVIDUse:
			if len(key.Certificates) != 1 {
				return nil, errs.New("expected a single certificate in x509-svid entry %d; got %d", i, len(key.Certificates))
			}
			bundle.AppendRootCA(key.Certificates[0])
		case jwtSVIDUse:
			if key.KeyID == "" {
				return nil, errs.New("missing key ID in jwt-svid entry %d", i)
			}
			if err := bundle.AppendJWTSigningKey(key.KeyID, key.Key); err != nil {
				return nil, errs.New("failed to add jwt-svid entry %d: %v", i, err)
			}
		case "":
			return nil, errs.New("missing use for key entry %d", i)
		default:
			return nil, errs.New("unrecognized use %q for key entry %d", key.Use, i)
		}
	}

	return bundle, nil
}
