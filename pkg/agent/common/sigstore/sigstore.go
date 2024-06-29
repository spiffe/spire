package sigstore

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/go-hclog"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	cosignremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/rekor/pkg/client"
	rekorclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
)

const (
	imageSignatureVerifiedSelector    = "image-signature:verified"
	imageAttestationsVerifiedSelector = "image-attestations:verified"
	publicRekorURL                    = "https://rekor.sigstore.dev"
)

var (
	oidcIssuerOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
)

type Verifier interface {
	// Verify verifies an image and returns a list of selectors.
	Verify(ctx context.Context, imageID string) ([]string, error)
}

// Config holds configuration for the ImageVerifier.
type Config struct {
	RekorURL            string
	RegistryCredentials map[string]*RegistryCredential

	AllowedIdentities  map[string][]string
	SkippedImages      []string
	IgnoreSCT          bool
	IgnoreTlog         bool
	IgnoreAttestations bool

	Logger hclog.Logger
}

type RegistryCredential struct {
	Username string
	Password string
}

// ImageVerifier implements the Verifier interface.
type ImageVerifier struct {
	config *Config

	verificationCache sync.Map
	allowedIdentities []cosign.Identity
	authOptions       map[string]remote.Option

	rekorClient         *rekorclient.Rekor
	fulcioRoots         *x509.CertPool
	fulcioIntermediates *x509.CertPool
	rekorPublicKeys     *cosign.TrustedTransparencyLogPubKeys
	ctLogPublicKeys     *cosign.TrustedTransparencyLogPubKeys

	hooks struct {
		verifyImageSignatures   verifySignaturesFn
		verifyImageAttestations verifyAttestationsFn
		getRekorClient          getRekorClientFn
		getFulcioRoots          getFulcioRootsFn
		getFulcioIntermediates  getFulcioIntermediatesFn
		getRekorPublicKeys      getRekorPublicKeysFn
		getCTLogPublicKeys      getCTLogPublicKeysFn
	}
}

func NewConfig() *Config {
	return &Config{
		AllowedIdentities: make(map[string][]string),
		SkippedImages:     make([]string, 0),
	}
}

func NewVerifier(config *Config) *ImageVerifier {
	verifier := &ImageVerifier{
		config:      config,
		authOptions: make(map[string]remote.Option),
		hooks: struct {
			verifyImageSignatures   verifySignaturesFn
			verifyImageAttestations verifyAttestationsFn
			getRekorClient          getRekorClientFn
			getFulcioRoots          getFulcioRootsFn
			getFulcioIntermediates  getFulcioIntermediatesFn
			getRekorPublicKeys      getRekorPublicKeysFn
			getCTLogPublicKeys      getCTLogPublicKeysFn
		}{
			verifyImageSignatures:   cosign.VerifyImageSignatures,
			verifyImageAttestations: cosign.VerifyImageAttestations,
			getRekorClient:          client.GetRekorClient,
			getFulcioRoots:          fulcioroots.Get,
			getFulcioIntermediates:  fulcioroots.GetIntermediates,
			getRekorPublicKeys:      cosign.GetRekorPubs,
			getCTLogPublicKeys:      cosign.GetCTLogPubs,
		},
	}

	if verifier.config.Logger == nil {
		verifier.config.Logger = hclog.Default()
	}

	if verifier.config.RekorURL == "" {
		verifier.config.RekorURL = publicRekorURL
	}

	verifier.allowedIdentities = processAllowedIdentities(config.AllowedIdentities)

	for registry, creds := range config.RegistryCredentials {
		if creds != nil && creds.Username != "" && creds.Password != "" {
			authOption := remote.WithAuth(&authn.Basic{
				Username: creds.Username,
				Password: creds.Password,
			})
			verifier.authOptions[registry] = authOption
		}
	}

	return verifier
}

// Init prepares the verifier by retrieving the Fulcio certificates and Rekor and CT public keys.
func (v *ImageVerifier) Init(ctx context.Context) error {
	var err error
	v.fulcioRoots, err = v.hooks.getFulcioRoots()
	if err != nil {
		return fmt.Errorf("failed to get fulcio root certificates: %w", err)
	}

	v.fulcioIntermediates, err = v.hooks.getFulcioIntermediates()
	if err != nil {
		return fmt.Errorf("failed to get fulcio intermediate certificates: %w", err)
	}

	if !v.config.IgnoreTlog {
		v.rekorPublicKeys, err = v.hooks.getRekorPublicKeys(ctx)
		if err != nil {
			return fmt.Errorf("failed to get rekor public keys: %w", err)
		}
		v.rekorClient, err = v.hooks.getRekorClient(v.config.RekorURL, client.WithLogger(v.config.Logger))
		if err != nil {
			return fmt.Errorf("failed to get rekor client: %w", err)
		}
	}

	if !v.config.IgnoreSCT {
		v.ctLogPublicKeys, err = v.hooks.getCTLogPublicKeys(ctx)
		if err != nil {
			return fmt.Errorf("failed to get CT log public keys: %w", err)
		}
	}

	return nil
}

// Verify validates image's signatures, attestations, and transparency logs using Cosign and Rekor.
// The imageID parameter is expected to be in the format "repository@sha256:digest".
// It returns selectors based on the image signature and rekor bundle details.
// Cosign ensures the image's signature issuer and subject match the configured allowed identities.
// If the image is in the skip list, it bypasses verification and returns an empty list of selectors.
// Uses a cache to avoid redundant verifications.
// An error is returned if the verification of the images signatures or attestations fails.
func (v *ImageVerifier) Verify(ctx context.Context, imageID string) ([]string, error) {
	v.config.Logger.Debug("Verifying image with sigstore", "image_id", imageID)

	// Check if the image is in the list of excluded images to determine if verification should be bypassed.
	if v.isSkippedImage(imageID) {
		// Return an empty list, indicating no verification was performed.
		return []string{}, nil
	}

	// Check the cache for previously verified selectors.
	if cachedSelectors, ok := v.verificationCache.Load(imageID); ok {
		if cachedSelectors != nil {
			v.config.Logger.Debug("Sigstore verifier cache hit", "image_id", imageID)
			return cachedSelectors.([]string), nil
		}
	}

	imageRef, err := name.ParseReference(imageID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference: %w", err)
	}

	registryURL := imageRef.Context().RegistryStr()
	authOption, exists := v.authOptions[registryURL]
	if !exists {
		authOption = remote.WithAuthFromKeychain(authn.DefaultKeychain)
	}

	checkOptions := &cosign.CheckOpts{
		RekorClient:        v.rekorClient,
		RootCerts:          v.fulcioRoots,
		IntermediateCerts:  v.fulcioIntermediates,
		RekorPubKeys:       v.rekorPublicKeys,
		CTLogPubKeys:       v.ctLogPublicKeys,
		Identities:         v.allowedIdentities,
		IgnoreSCT:          v.config.IgnoreSCT,
		IgnoreTlog:         v.config.IgnoreTlog,
		RegistryClientOpts: []cosignremote.Option{cosignremote.WithRemoteOptions(authOption)},
	}

	var selectors []string

	signatures, err := v.verifySignatures(ctx, imageRef, checkOptions)
	if err != nil {
		return nil, err
	}
	selectors = append(selectors, imageSignatureVerifiedSelector)

	if !v.config.IgnoreAttestations {
		attestations, err := v.verifyAttestations(ctx, imageRef, checkOptions)
		if err != nil {
			return nil, err
		}
		if len(attestations) > 0 {
			selectors = append(selectors, imageAttestationsVerifiedSelector)
		}
	}

	detailsList, err := v.extractDetailsFromSignatures(signatures)
	if err != nil {
		return nil, fmt.Errorf("failed to extract details from signatures for image %q: %w", imageID, err)
	}

	selectors = append(selectors, formatDetailsAsSelectors(detailsList)...)

	v.verificationCache.Store(imageID, selectors)

	return selectors, nil
}

type verifySignaturesFn func(ctx context.Context, imageRef name.Reference, checkOptions *cosign.CheckOpts) ([]oci.Signature, bool, error)
type verifyAttestationsFn func(ctx context.Context, signedImgRef name.Reference, co *cosign.CheckOpts) (checkedAttestations []oci.Signature, bundleVerified bool, err error)
type getRekorClientFn func(string, ...client.Option) (*rekorclient.Rekor, error)
type getFulcioRootsFn func() (*x509.CertPool, error)
type getFulcioIntermediatesFn func() (*x509.CertPool, error)
type getRekorPublicKeysFn func(context.Context) (*cosign.TrustedTransparencyLogPubKeys, error)
type getCTLogPublicKeysFn func(context.Context) (*cosign.TrustedTransparencyLogPubKeys, error)

type signatureDetails struct {
	Subject              string
	Issuer               string
	Signature            string
	LogID                string
	LogIndex             string
	IntegratedTime       string
	SignedEntryTimestamp string
}

func (v *ImageVerifier) verifySignatures(ctx context.Context, imageRef name.Reference, checkOptions *cosign.CheckOpts) ([]oci.Signature, error) {
	v.config.Logger.Debug("Verifying image signatures", "image_id", imageRef.Name())

	// Verify the image's signatures using cosign.VerifySignatures
	signatures, bundleVerified, err := v.hooks.verifyImageSignatures(ctx, imageRef, checkOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to verify signatures: %w", err)
	}
	if !bundleVerified && !v.config.IgnoreTlog {
		return nil, fmt.Errorf("rekor bundle not verified for image: %s", imageRef.Name())
	}
	if len(signatures) == 0 {
		return nil, fmt.Errorf("no verified signature returned by cosign for image: %s", imageRef.Name())
	}

	return signatures, nil
}

func (v *ImageVerifier) verifyAttestations(ctx context.Context, imageRef name.Reference, checkOptions *cosign.CheckOpts) ([]oci.Signature, error) {
	v.config.Logger.Debug("Verifying image attestations", "image_id", imageRef.Name())

	// Verify the image's attestations using cosign.VerifyImageAttestations
	attestations, bundleVerified, err := v.hooks.verifyImageAttestations(ctx, imageRef, checkOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to verify image attestations: %w", err)
	}
	if len(attestations) > 0 && !bundleVerified && !v.config.IgnoreTlog {
		return nil, fmt.Errorf("rekor bundle not verified for image: %s", imageRef.Name())
	}

	return attestations, nil
}

func (v *ImageVerifier) isSkippedImage(imageID string) bool {
	for _, id := range v.config.SkippedImages {
		if id == imageID {
			return true
		}
	}
	return false
}

func (v *ImageVerifier) extractDetailsFromSignatures(signatures []oci.Signature) ([]*signatureDetails, error) {
	var detailsList []*signatureDetails
	for _, signature := range signatures {
		details, err := extractSignatureDetails(signature, v.config.IgnoreTlog)
		if err != nil {
			return nil, err
		}
		detailsList = append(detailsList, details)
	}
	return detailsList, nil
}

func extractSignatureDetails(signature oci.Signature, ignoreTlog bool) (*signatureDetails, error) {
	cert, err := getCertificate(signature)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate from signature: %w", err)
	}

	subject, err := extractSubject(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to extract subject from certificate: %w", err)
	}

	issuer, err := extractIssuer(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to extract issuer from certificate: %w", err)
	}

	base64Signature, err := signature.Base64Signature()
	if err != nil {
		return nil, fmt.Errorf("failed to extract base64 signature from certificate: %w", err)
	}

	var logIndex string
	var logID string
	var signedEntryTimestamp string
	var integratedTime string
	if !ignoreTlog {
		rekorBundle, err := signature.Bundle()
		if err != nil {
			return nil, fmt.Errorf("failed to get signature rekor bundle: %w", err)
		}

		logID = rekorBundle.Payload.LogID
		logIndex = strconv.FormatInt(rekorBundle.Payload.LogIndex, 10)
		integratedTime = strconv.FormatInt(rekorBundle.Payload.IntegratedTime, 10)
		signedEntryTimestamp = base64.StdEncoding.EncodeToString(rekorBundle.SignedEntryTimestamp)
	}

	return &signatureDetails{
		Subject:              subject,
		Issuer:               issuer,
		Signature:            base64Signature,
		LogID:                logID,
		LogIndex:             logIndex,
		IntegratedTime:       integratedTime,
		SignedEntryTimestamp: signedEntryTimestamp,
	}, nil
}

func getCertificate(signature oci.Signature) (*x509.Certificate, error) {
	if signature == nil {
		return nil, errors.New("signature is nil")
	}
	cert, err := signature.Cert()
	if err != nil {
		return nil, fmt.Errorf("failed to access signature certificate: %w", err)
	}
	if cert == nil {
		return nil, errors.New("no certificate found in signature")
	}
	return cert, nil
}

func extractSubject(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", errors.New("certificate is nil")
	}

	subjectAltNames := cryptoutils.GetSubjectAlternateNames(cert)
	if len(subjectAltNames) > 0 {
		for _, san := range subjectAltNames {
			if san != "" {
				return san, nil
			}
		}
		return "", errors.New("subject alternative names are present but all are empty")
	}

	return "", errors.New("no subject found in certificate")
}

func extractIssuer(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", errors.New("certificate is nil")
	}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidcIssuerOID) {
			issuer := string(ext.Value)
			if issuer == "" {
				return "", errors.New("OIDC issuer extension is present but empty")
			}
			return issuer, nil
		}
	}

	return "", errors.New("no OIDC issuer found in certificate extensions")
}

func formatDetailsAsSelectors(detailsList []*signatureDetails) []string {
	var selectors []string
	for _, details := range detailsList {
		selectors = append(selectors, detailsToSelectors(details)...)
	}
	return selectors
}

func detailsToSelectors(details *signatureDetails) []string {
	var selectors []string
	if details.Subject != "" {
		selectors = append(selectors, fmt.Sprintf("image-signature-subject:%s", details.Subject))
	}
	if details.Issuer != "" {
		selectors = append(selectors, fmt.Sprintf("image-signature-issuer:%s", details.Issuer))
	}
	if details.Signature != "" {
		selectors = append(selectors, fmt.Sprintf("image-signature-value:%s", details.Signature))
	}
	if details.LogID != "" {
		selectors = append(selectors, fmt.Sprintf("image-signature-log-id:%s", details.LogID))
	}
	if details.LogIndex != "" {
		selectors = append(selectors, fmt.Sprintf("image-signature-log-index:%s", details.LogIndex))
	}
	if details.IntegratedTime != "" {
		selectors = append(selectors, fmt.Sprintf("image-signature-integrated-time:%s", details.IntegratedTime))
	}
	if details.SignedEntryTimestamp != "" {
		selectors = append(selectors, fmt.Sprintf("image-signature-signed-entry-timestamp:%s", details.SignedEntryTimestamp))
	}
	return selectors
}

func processAllowedIdentities(allowedIdentities map[string][]string) []cosign.Identity {
	var identities []cosign.Identity
	for issuer, subjects := range allowedIdentities {
		for _, subject := range subjects {
			identity := cosign.Identity{}

			if containsRegexChars(issuer) {
				identity.IssuerRegExp = issuer
			} else {
				identity.Issuer = issuer
			}

			if containsRegexChars(subject) {
				identity.SubjectRegExp = subject
			} else {
				identity.Subject = subject
			}

			identities = append(identities, identity)
		}
	}
	return identities
}

func containsRegexChars(s string) bool {
	// check for characters commonly used in regex.
	return strings.ContainsAny(s, "*+?^${}[]|()")
}
