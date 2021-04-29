package vc

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ecdsasecp256k1signature2019"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

// SignCredential creates a verifiable credential by adding a proof to the credential.
func SignCredential(credential []byte, privKey []byte, opts *ProofOptions) ([]byte, error) {
	cred, err := verifiable.ParseCredential(credential, verifiable.WithDisabledProofCheck())
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	if err := addProof(cred, privKey, opts); err != nil {
		return nil, fmt.Errorf("failed to add proof to credential: %w", err)
	}

	return cred.MarshalJSON()
}

// VerifyCredential verifies a proof in the verifiable credential.
func VerifyCredential(vc []byte, pubKey []byte, pubKeyType string) error {
	_, err := verifiable.ParseCredential(
		vc,
		verifiable.WithPublicKeyFetcher(verifiable.SingleKey(pubKey, pubKeyType)),
	)
	if err != nil {
		return fmt.Errorf("failed to verify credential: %w", err)
	}
	return nil
}

// DeriveCredential derives a new verifiable credential using selection disclosure (to be implemented).
func DeriveCredential(vc []byte) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// SignPresentation creates a verifiable presentation by adding a proof to the presentation.
func SignPresentation(presentation []byte, privKey []byte, opts *ProofOptions) ([]byte, error) {
	pres, err := verifiable.ParsePresentation(presentation, verifiable.WithPresDisabledProofCheck())
	if err != nil {
		return nil, fmt.Errorf("failed to parse presentation: %w", err)
	}

	if err := addProof(pres, privKey, opts); err != nil {
		return nil, fmt.Errorf("failed to add proof to presentation: %w", err)
	}

	return pres.MarshalJSON()
}

// VerifyPresentation verifies a proof in the verifiable presentation.
func VerifyPresentation(vp []byte, pubKey []byte, pubKeyType string) error {
	_, err := verifiable.ParsePresentation(
		vp,
		verifiable.WithPresPublicKeyFetcher(verifiable.SingleKey(pubKey, pubKeyType)),
	)
	if err != nil {
		return fmt.Errorf("failed to verify presentation: %w", err)
	}
	return nil
}

// GetCredentials returns a Iterator that contains verifiable credentials in the verifiable presentation.
func GetCredentials(presentation []byte) (*Iterator, error) {
	pres, err := verifiable.ParsePresentation(presentation, verifiable.WithPresDisabledProofCheck())
	if err != nil {
		return nil, fmt.Errorf("failed to parse presentation: %w", err)
	}

	credentials := pres.Credentials()

	jsonCredentials := make([][]byte, 0, len(credentials))
	for _, credential := range pres.Credentials() {
		jsonCredential, err := json.Marshal(credential)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal a credential to JSON: %w", err)
		}

		jsonCredentials = append(jsonCredentials, jsonCredential)
	}

	return newIterator(jsonCredentials), nil
}

// provable is an interface that represent the return value of ParseCredential() and ParsePresentation() defined in the aries-framework-go.
// This type can be passed to the AddLinkedDataProof() defined in the aries-framework-go.
type provable interface {
	AddLinkedDataProof(context *verifiable.LinkedDataProofContext, jsonldOpts ...jsonld.ProcessorOpts) error
}

// ProofOptions is model to allow the dynamic proofing options by the user.
type ProofOptions struct {
	VerificationMethod string `json:"verificationMethod,omitempty"`
	SignatureType      string `json:"signatureType,omitempty"`
	Domain             string `json:"domain,omitempty"`
	Challenge          string `json:"challenge,omitempty"`
}

func addProof(provableData provable, privKey []byte, opts *ProofOptions) error {
	// TODO: support more sig types
	sigSuite := ecdsasecp256k1signature2019.New(suite.WithSigner(newSecp256k1Signer(privKey)))

	signingCtx := &verifiable.LinkedDataProofContext{
		VerificationMethod:      opts.VerificationMethod,
		SignatureRepresentation: verifiable.SignatureProofValue,
		SignatureType:           opts.SignatureType,
		Suite:                   sigSuite,
		Domain:                  opts.Domain,
		Challenge:               opts.Challenge,
	}
	return provableData.AddLinkedDataProof(signingCtx)
}
