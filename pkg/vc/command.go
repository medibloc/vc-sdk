package vc

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ecdsasecp256k1signature2019"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

// SignCredential creates a Verifiable Credential by adding a proof to the Credential.
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

// DeriveCredential derives a new Verifiable Credential using selection disclosure (to be implemented).
func DeriveCredential(vc []byte) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// SignPresentation creates a Verifiable Presentation by adding a proof to the Presentation.
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

type provable interface {
	AddLinkedDataProof(context *verifiable.LinkedDataProofContext, jsonldOpts ...jsonld.ProcessorOpts) error
}

// ProofOptions is model to allow the dynamic proofing options by the user.
type ProofOptions struct {
	VerificationMethod string `json:"verificationMethod,omitempty"`
	Domain             string `json:"domain,omitempty"`
	Challenge          string `json:"challenge,omitempty"`
	SignatureType      string `json:"signatureType,omitempty"`
}

func addProof(provableData provable, privKey []byte, opts *ProofOptions) error {
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
