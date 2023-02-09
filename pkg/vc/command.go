package vc

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"

	controllerverifiable "github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ecdsasecp256k1signature2019"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

// SignCredential creates a verifiable credential by adding a proof to the credential.
func (f *Framework) SignCredential(credential []byte, privKey []byte, opts *ProofOptions) ([]byte, error) {
	cred, err := verifiable.ParseCredential(
		credential, verifiable.WithDisabledProofCheck(), verifiable.WithJSONLDDocumentLoader(f.loader))

	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	if err := f.addProof(cred, privKey, opts); err != nil {
		return nil, fmt.Errorf("failed to add proof to credential: %w", err)
	}

	return cred.MarshalJSON()
}

// VerifyCredential verifies a proof in the verifiable credential.
func (f *Framework) VerifyCredential(vc []byte, pubKey []byte, pubKeyType string) error {
	_, err := verifiable.ParseCredential(
		vc,
		verifiable.WithPublicKeyFetcher(verifiable.SingleKey(pubKey, pubKeyType)),
		verifiable.WithJSONLDDocumentLoader(f.loader),
	)
	if err != nil {
		return fmt.Errorf("failed to verify credential: %w", err)
	}
	return nil
}

// DeriveCredential derives a new verifiable credential using selection disclosure (to be implemented).
func (f *Framework) DeriveCredential(vc []byte, frame []byte, nonce []byte, issuerPubKey []byte, issuerPubKeyType string) ([]byte, error) {
	cred, err := verifiable.ParseCredential(vc, verifiable.WithDisabledProofCheck(), verifiable.WithJSONLDDocumentLoader(f.loader))
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
		verifiable.WithJSONLDDocumentLoader(f.loader),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate BBS selective disclosure: %w", err)
	}

	return derived.MarshalJSON()
}

// CreatePresentationFromPD creates verifiable presentation based on presentation definition.
func (f *Framework) CreatePresentationFromPD(credential []byte, pdBz []byte) (*verifiable.Presentation, error) {
	cred, err := verifiable.ParseCredential(
		credential, verifiable.WithDisabledProofCheck(), verifiable.WithJSONLDDocumentLoader(f.loader))
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	pd, err := parsePresentationDefinition(pdBz)
	if err != nil {
		return nil, fmt.Errorf("failed to parse presentation definition: %w", err)
	}

	return pd.CreateVP([]*verifiable.Credential{cred}, f.loader, verifiable.WithJSONLDDocumentLoader(f.loader))
}

// SignPresentation creates a verifiable presentation by adding a proof to the presentation.
func (f *Framework) SignPresentation(presentation []byte, privKey []byte, opts *ProofOptions) ([]byte, error) {
	pres, err := verifiable.ParsePresentation(presentation, verifiable.WithPresDisabledProofCheck(), verifiable.WithPresJSONLDDocumentLoader(f.loader))
	if err != nil {
		return nil, fmt.Errorf("failed to parse presentation: %w", err)
	}

	if err := f.addProof(pres, privKey, opts); err != nil {
		return nil, fmt.Errorf("failed to add proof to presentation: %w", err)
	}

	return pres.MarshalJSON()
}

// VerifyPresentation verifies a proof in the verifiable presentation.
// If there is a presentation definition, also verifies that the presentation meets the requirements.
func (f *Framework) VerifyPresentation(vp []byte, pubKey []byte, pubKeyType string, pdBz []byte) error {
	presentation, err := verifiable.ParsePresentation(
		vp,
		verifiable.WithPresPublicKeyFetcher(verifiable.SingleKey(pubKey, pubKeyType)),
		verifiable.WithPresJSONLDDocumentLoader(f.loader),
	)
	if err != nil {
		return fmt.Errorf("failed to verify presentation: %w", err)
	}

	if pdBz != nil {
		pd, err := parsePresentationDefinition(pdBz)
		if err != nil {
			return fmt.Errorf("failed to parse presentation definition: %w", err)
		}

		// TODO: For now, check of constraints in presentation definition is not supported
		// https://github.com/hyperledger/aries-framework-go/issues/2108
		_, err = pd.Match(presentation, f.loader, presexch.WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(f.loader)))
		if err != nil {
			return fmt.Errorf("is not matched with presentation definition: %w", err)
		}
	}

	return nil
}

// GetCredentials returns a Iterator that contains verifiable credentials in the verifiable presentation.
func (f *Framework) GetCredentials(presentation []byte) (*Iterator, error) {
	pres, err := verifiable.ParsePresentation(presentation, verifiable.WithPresDisabledProofCheck(), verifiable.WithPresJSONLDDocumentLoader(f.loader))
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

func (f *Framework) GetCredentialProofs(vc []byte) (*ProofIterator, error) {
	parsed, err := verifiable.ParseCredential(vc, verifiable.WithDisabledProofCheck(), verifiable.WithJSONLDDocumentLoader(f.loader))
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	return parseProofs(parsed.Proofs)
}

func (f *Framework) GetPresentationProofs(vp []byte) (*ProofIterator, error) {
	parsed, err := verifiable.ParsePresentation(vp, verifiable.WithPresDisabledProofCheck(), verifiable.WithPresJSONLDDocumentLoader(f.loader))
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

func (f *Framework) addProof(provableData provable, privKey []byte, opts *ProofOptions) error {
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
	return provableData.AddLinkedDataProof(signingCtx, jsonld.WithDocumentLoader(f.loader))
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

func parsePresentationDefinition(pdBz []byte) (*presexch.PresentationDefinition, error) {
	var pd *presexch.PresentationDefinition

	if err := json.Unmarshal(pdBz, &pd); err != nil {
		return nil, fmt.Errorf("failed to unmarshal presentation definition: %w", err)
	}

	if err := pd.ValidateSchema(); err != nil {
		return nil, fmt.Errorf("invalid presentation definition")
	}

	return pd, nil
}
