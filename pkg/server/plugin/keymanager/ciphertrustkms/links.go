package ciphertrustkms

import (
	"time"
)

// LinksEndpoint wraps the /vault/links endpoint.
//type LinksEndpoint Client

const (
	// PrivKeyLink is the link to a Private Key
	PrivKeyLink LinkType = "privateKey"
	// PubKeyLink is the link to a Public Key
	PubKeyLink LinkType = "publicKey"
	// CertLink is the link to a Certificate
	CertLink LinkType = "certificate"
	// DerivationBaseObjLink is the link to a Derivation Base object
	DerivationBaseObjLink LinkType = "derivationBaseObject"
	// DerivedKeyLink is the link to a Derived Key
	DerivedKeyLink LinkType = "derivedKey"
	// ReplacementObjLink is the link to a Replacement object
	ReplacementObjLink LinkType = "replacementObject"
	// ReplacedObjLink is the link to a Replaced object
	ReplacedObjLink LinkType = "replacedObject"
	// ParentLink is the link to a Parent Key
	ParentLink LinkType = "parent"
	// ChildLink is the link to a Child Key
	ChildLink LinkType = "child"
	// PreviousLink is the link to a  Previous Key
	PreviousLink LinkType = "previous"
	// NextLink is the link to a Next Key
	NextLink LinkType = "next"
	// Index is a unique index per source
	Index LinkType = "index"
	// PKCS12CertificateLink is the link to a Certificate for pkcs#12 conformant blob
	PKCS12CertificateLink LinkType = "pkcs12Certificate"
	// PKCS12PasswordLink is the link to a Password(SecretData) for pkcs#12 conformant blob
	PKCS12PasswordLink LinkType = "pkcs12Password"
)

// LinkType type
type LinkType string

// LinkParams Parameters used for create and update a Link
type LinkParams struct {
	Type         LinkType `json:"type"`
	Source       string   `json:"source"`
	IDTypeSource string   `json:"idTypeSource,omitempty"`
	Target       string   `json:"target"`
	IDTypeTarget string   `json:"idTypeTarget,omitempty"`
}

// Link represents a link between the source and target
type Link struct {
	Resource
	UpdatedAt time.Time `json:"updatedAt"`
	Type      LinkType  `json:"type"`
	Source    string    `json:"source"`
	SourceID  string    `json:"sourceID"`
	Target    string    `json:"target"`
	TargetID  string    `json:"targetID"`
	Index     int       `json:"index"`
}

// ListLinksParams Parameters used for list links
type ListLinksParams struct {
	Skip   int      `json:"-" url:"skip,omitempty"`
	Limit  int      `json:"-" url:"limit,omitempty"`
	Type   LinkType `json:"-" url:"type,omitempty"`
	Source string   `json:"-" url:"source,omitempty"`
	Target string   `json:"-" url:"target,omitempty"`
	Index  *int     `json:"-" url:"index,omitempty"`
}

// LinksPage is the response to commands that return a set of links
type LinksPage struct {
	PagingInfo
	Resources []Link `json:"resources"`
}

// SlingWithCtx returns an object you can use to make requests on the links
// endpoint which are not yet reflected in the methods.
//
// Deprecated: use requester.Requester methods instead
/*
func (l *LinksEndpoint) SlingWithCtx(ctx context.Context) *sling.Sling {
	return (*Client)(l).SlingWithCtx(ctx).Path(l.VaultPrefix).Path(l.LinksPrefix)
}

// Create a Link
func (l *LinksEndpoint) Create(ctx context.Context, params LinkParams) (*Link, *http.Response, error) {
	var link Link
	resp, _, err := l.ReceiveContext(ctx, &link, requester.Body(params), requester.Post(l.VaultPrefix, l.LinksPrefix))
	return &link, resp, err
}

// Get a Link
// `identifier` is the Link ID/URI
func (l *LinksEndpoint) Get(ctx context.Context, identifier string) (*Link, *http.Response, error) {
	var link Link
	resp, _, err := l.ReceiveContext(ctx, &link, requester.Get(l.VaultPrefix, l.LinksPrefix+url.PathEscape(identifier)))
	return &link, resp, err
}

// List gets list of Link, with filter options
func (l *LinksEndpoint) List(ctx context.Context, params ListLinksParams) ([]Link, PagingInfo, *http.Response, error) {
	results := LinksPage{}
	resp, _, err := l.ReceiveContext(ctx, &results, requester.QueryParams(params),
		requester.Get(l.VaultPrefix, l.LinksPrefix),
	)
	return results.Resources, results.PagingInfo, resp, err
}

// Update a Link
func (l *LinksEndpoint) Update(ctx context.Context, identifier string, params LinkParams) (*Link, *http.Response, error) {
	var link Link
	resp, _, err := l.ReceiveContext(ctx, &link, requester.Body(params),
		requester.Patch(l.VaultPrefix, l.LinksPrefix+url.PathEscape(identifier)),
	)
	return &link, resp, err
}

// Delete a Link
// `identifier` is the Link ID
func (l *LinksEndpoint) Delete(ctx context.Context, identifier string) (*http.Response, error) {
	resp, _, err := l.ReceiveContext(ctx, requester.Delete(l.VaultPrefix, l.LinksPrefix, url.PathEscape(identifier)))
	return resp, err
}
*/
