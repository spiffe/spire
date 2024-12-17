package bundleutil

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func Decode(trustDomain spiffeid.TrustDomain, r io.Reader) (*spiffebundle.Bundle, error) {
	doc := new(bundleDoc)
	if err := json.NewDecoder(r).Decode(doc); err != nil {
		return nil, fmt.Errorf("failed to decode bundle: %w", err)
	}
	return unmarshal(trustDomain, doc)
}

func Unmarshal(trustDomain spiffeid.TrustDomain, data []byte) (*spiffebundle.Bundle, error) {
	doc := new(bundleDoc)
	if err := json.Unmarshal(data, doc); err != nil {
		return nil, err
	}
	return unmarshal(trustDomain, doc)
}

func unmarshal(trustDomain spiffeid.TrustDomain, doc *bundleDoc) (*spiffebundle.Bundle, error) {
	bundle := spiffebundle.New(trustDomain)
	bundle.SetRefreshHint(time.Second * time.Duration(doc.RefreshHint))

	for i, key := range doc.Keys {
		switch key.Use {
		case x509SVIDUse:
			if len(key.Certificates) != 1 {
				return nil, fmt.Errorf("expected a single certificate in x509-svid entry %d; got %d", i, len(key.Certificates))
			}
			bundle.AddX509Authority(key.Certificates[0])
		case jwtSVIDUse:
			if key.KeyID == "" {
				return nil, fmt.Errorf("missing key ID in jwt-svid entry %d", i)
			}
			if err := bundle.AddJWTAuthority(key.KeyID, key.Key); err != nil {
				return nil, fmt.Errorf("failed to add jwt-svid entry %d: %w", i, err)
			}
		case "":
			return nil, fmt.Errorf("missing use for key entry %d", i)
		default:
			return nil, fmt.Errorf("unrecognized use %q for key entry %d", key.Use, i)
		}
	}

	return bundle, nil
}
