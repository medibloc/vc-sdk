package vc

import (
	"encoding/json"
	"fmt"
	"time"

	controllerverifiable "github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	ld "github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ecdsasecp256k1signature2019"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

// SignCredential creates a verifiable credential by adding a proof to the credential.
func SignCredential(credential []byte, privKey []byte, opts *ProofOptions, documentLoader ld.DocumentLoader) ([]byte, error) {
	cred, err := verifiable.ParseCredential(credential, verifiable.WithDisabledProofCheck(), verifiable.WithJSONLDDocumentLoader(documentLoader))
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	if err := addProof(cred, privKey, opts, documentLoader); err != nil {
		return nil, fmt.Errorf("failed to add proof to credential: %w", err)
	}

	return cred.MarshalJSON()
}

// VerifyCredential verifies a proof in the verifiable credential.
func VerifyCredential(vc []byte, pubKey []byte, pubKeyType string, documentLoader ld.DocumentLoader) error {
	_, err := verifiable.ParseCredential(
		vc,
		verifiable.WithPublicKeyFetcher(verifiable.SingleKey(pubKey, pubKeyType)),
		verifiable.WithJSONLDDocumentLoader(documentLoader),
	)
	if err != nil {
		return fmt.Errorf("failed to verify credential: %w", err)
	}
	return nil
}

// DeriveCredential derives a new verifiable credential using selection disclosure (to be implemented).
func DeriveCredential(vc []byte, frame []byte, nonce []byte, issuerPubKey []byte, issuerPubKeyType string, documentLoader ld.DocumentLoader) ([]byte, error) {
	cred, err := verifiable.ParseCredential(vc, verifiable.WithDisabledProofCheck(), verifiable.WithJSONLDDocumentLoader(documentLoader))
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	frameMap := make(map[string]interface{})
	if err := json.Unmarshal(frame, &frameMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal frame: %w", err)
	}

	derived, err := cred.GenerateBBSSelectiveDisclosure(
		frameMap,
		nonce,
		verifiable.WithPublicKeyFetcher(verifiable.SingleKey(issuerPubKey, issuerPubKeyType)),
		verifiable.WithJSONLDDocumentLoader(documentLoader),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate BBS selective disclosure: %w", err)
	}

	return derived.MarshalJSON()
}

// SignPresentation creates a verifiable presentation by adding a proof to the presentation.
func SignPresentation(presentation []byte, privKey []byte, opts *ProofOptions, documentLoader ld.DocumentLoader) ([]byte, error) {
	pres, err := verifiable.ParsePresentation(presentation, verifiable.WithPresDisabledProofCheck(), verifiable.WithPresJSONLDDocumentLoader(documentLoader))
	if err != nil {
		return nil, fmt.Errorf("failed to parse presentation: %w", err)
	}

	if err := addProof(pres, privKey, opts, documentLoader); err != nil {
		return nil, fmt.Errorf("failed to add proof to presentation: %w", err)
	}

	return pres.MarshalJSON()
}

// VerifyPresentation verifies a proof in the verifiable presentation.
func VerifyPresentation(vp []byte, pubKey []byte, pubKeyType string, documentLoader ld.DocumentLoader) error {
	_, err := verifiable.ParsePresentation(
		vp,
		verifiable.WithPresPublicKeyFetcher(verifiable.SingleKey(pubKey, pubKeyType)),
		verifiable.WithPresJSONLDDocumentLoader(documentLoader),
	)
	if err != nil {
		return fmt.Errorf("failed to verify presentation: %w", err)
	}
	return nil
}

// GetCredentials returns a Iterator that contains verifiable credentials in the verifiable presentation.
func GetCredentials(presentation []byte, documentLoader ld.DocumentLoader) (*Iterator, error) {
	pres, err := verifiable.ParsePresentation(presentation, verifiable.WithPresDisabledProofCheck(), verifiable.WithPresJSONLDDocumentLoader(documentLoader))
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

func GetCredentialProofs(vc []byte, documentLoader ld.DocumentLoader) (*ProofIterator, error) {
	parsed, err := verifiable.ParseCredential(vc, verifiable.WithDisabledProofCheck(), verifiable.WithJSONLDDocumentLoader(documentLoader))
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	return parseProofs(parsed.Proofs)
}

func GetPresentationProofs(vp []byte, documentLoader ld.DocumentLoader) (*ProofIterator, error) {
	parsed, err := verifiable.ParsePresentation(vp, verifiable.WithPresDisabledProofCheck(), verifiable.WithPresJSONLDDocumentLoader(documentLoader))
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	return parseProofs(parsed.Proofs)
}

func parseProofs(rawProofs []verifiable.Proof) (*ProofIterator, error) {
	proofs := make([]*Proof, 0)
	for _, p := range rawProofs {
		proof, err := newProof(p)
		if err != nil {
			return nil, fmt.Errorf("failed to newProof: %w", err)
		}
		proofs = append(proofs, proof)
	}

	return newProofIterator(proofs), nil
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
	ProofPurpose       string `json:"proofPurpose,omitempty"`
	Created            string `json:"created,omitempty"`
	Domain             string `json:"domain,omitempty"`
	Challenge          string `json:"challenge,omitempty"`
}

const (
	EcdsaSecp256k1Signature2019 = "EcdsaSecp256k1Signature2019"
)

func addProof(provableData provable, privKey []byte, opts *ProofOptions, loader ld.DocumentLoader) error {
	var sigSuite signer.SignatureSuite

	switch opts.SignatureType {
	case EcdsaSecp256k1Signature2019:
		sigSuite = ecdsasecp256k1signature2019.New(suite.WithSigner(newSecp256k1Signer(privKey)))
	case controllerverifiable.BbsBlsSignature2020:
		sigSuite = bbsblssignature2020.New(suite.WithSigner(newBbsSigner(privKey)))
	default:
		return fmt.Errorf("signature type unsupported: %s", opts.SignatureType)
	}

	var created *time.Time = nil
	if opts.Created != "" {
		ts, err := time.Parse(time.RFC3339, opts.Created)
		if err != nil {
			return fmt.Errorf("failed to parse 'created' time: %w", err)
		}
		created = &ts
	}

	signingCtx := &verifiable.LinkedDataProofContext{
		VerificationMethod:      opts.VerificationMethod,
		SignatureRepresentation: verifiable.SignatureProofValue,
		SignatureType:           opts.SignatureType,
		Suite:                   sigSuite,
		Purpose:                 opts.ProofPurpose,
		Created:                 created,
		Domain:                  opts.Domain,
		Challenge:               opts.Challenge,
	}
	return provableData.AddLinkedDataProof(signingCtx, jsonld.WithDocumentLoader(loader))
}

// Proof is a LD Proof struct: https://w3c-ccg.github.io/ld-proofs/
type Proof struct {
	VerificationMethod string `json:"verificationMethod"`
	Type               string `json:"type"`
	ProofPurpose       string `json:"proofPurpose"`
	Created            string `json:"created"`
	Domain             string `json:"domain,omitempty"`
	Challenge          string `json:"challenge,omitempty"`
}

func newProof(p verifiable.Proof) (*Proof, error) {
	proof := &Proof{}
	var ok bool

	proof.VerificationMethod, ok = stringFromMap(p, "verificationMethod")
	if !ok {
		return nil, fmt.Errorf("failed to find verificationMethod")
	}
	proof.Type, ok = stringFromMap(p, "type")
	if !ok {
		return nil, fmt.Errorf("failed to find type")
	}
	proof.ProofPurpose, ok = stringFromMap(p, "proofPurpose")
	if !ok {
		return nil, fmt.Errorf("failed to find proofPurpose")
	}
	proof.Created, ok = stringFromMap(p, "created")
	if !ok {
		return nil, fmt.Errorf("failed to find created")
	}
	proof.Domain, _ = stringFromMap(p, "domain")
	proof.Challenge, _ = stringFromMap(p, "challenge")

	return proof, nil
}

func stringFromMap(m map[string]interface{}, k string) (string, bool) {
	v, ok := m[k]
	if !ok {
		return "", false
	}

	if v == nil {
		return "", false
	}
	return v.(string), true
}
