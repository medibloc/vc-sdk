package vc

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	ld "github.com/piprate/json-gold/ld"
)

// Credential is a helper model to assemble an W3C compatible JSON document.
type Credential struct {
	Context               string
	ID                    string
	Type                  string
	Issuer                string
	IssuedAt              string
	ExpiresAt             string
	CredentialSubjectJSON []byte
}

// MarshalJSON returns a JSON document compatible with the W3C standard.
func (c *Credential) MarshalJSON() ([]byte, error) {
	ariesCredential, err := c.toAriesCredential()
	if err != nil {
		return nil, fmt.Errorf("failed to covert into AriesCredential: %w", err)
	}
	return ariesCredential.MarshalJSON()
}

func (c *Credential) toAriesCredential() (*verifiable.Credential, error) {
	issuedAt, err := toAriesTime(c.IssuedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IssuedAt: %w", err)
	}
	expiresAt, err := toAriesTime(c.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ExpiresAt: %w", err)
	}

	var credentialSubject map[string]json.RawMessage
	if err := json.Unmarshal(c.CredentialSubjectJSON, &credentialSubject); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CredentialSubjectJSON: %w", err)
	}

	return &verifiable.Credential{
		Context: []string{"https://www.w3.org/2018/credentials/v1", c.Context},
		ID:      c.ID,
		Types:   []string{"VerifiableCredential", c.Type},
		Issuer:  verifiable.Issuer{ID: c.Issuer},
		Issued:  issuedAt,
		Expired: expiresAt,
		Subject: credentialSubject,
	}, nil
}

func toAriesTime(str string) (*util.TimeWrapper, error) {
	if str == "" {
		return nil, nil
	}

	t, err := time.Parse(time.RFC3339, str)
	if err != nil {
		return nil, fmt.Errorf("failed to parse time: %w", err)
	}
	return util.NewTime(t), nil
}

// Presentation is a helper model to assemble an W3C compatible JSON document.
type Presentation struct {
	ID                    string
	Holder                string
	verifiableCredentials []*verifiable.Credential
}

// AddVerifiableCredential adds a raw JSON of a verifiable credential to the Presentation.
func (p *Presentation) AddVerifiableCredential(vcBytes []byte, documentLoader ld.DocumentLoader) error {
	vc, err := verifiable.ParseCredential(vcBytes, verifiable.WithDisabledProofCheck(), verifiable.WithJSONLDDocumentLoader(documentLoader))
	if err != nil {
		return fmt.Errorf("failed to parse verifiable credential: %w", err)
	}

	p.verifiableCredentials = append(p.verifiableCredentials, vc)
	return nil
}

// MarshalJSON returns a JSON document compatible with the W3C standard.
func (p *Presentation) MarshalJSON() ([]byte, error) {
	ariesPresentation, err := p.toAriesPresentation()
	if err != nil {
		return nil, fmt.Errorf("failed to convert into AriesPresentation: %w", err)
	}
	return ariesPresentation.MarshalJSON()
}

func (p *Presentation) toAriesPresentation() (*verifiable.Presentation, error) {
	presentation, err := verifiable.NewPresentation(
		verifiable.WithCredentials(p.verifiableCredentials...),
	)
	if err != nil {
		return nil, err
	}

	presentation.ID = p.ID
	presentation.Holder = p.Holder

	return presentation, nil
}

// Iterator is an iterator of byte slices (because gomobile doesn't support slice types except 1-D []byte).
type Iterator struct {
	items [][]byte
	index int
}

func newIterator(items [][]byte) *Iterator {
	return &Iterator{
		items: items,
		index: 0,
	}
}

func (i *Iterator) len() int {
	if i.items == nil {
		return 0
	}
	return len(i.items)
}

func (i *Iterator) HasNext() bool {
	return i.index < i.len()
}

func (i *Iterator) Next() []byte {
	if !i.HasNext() {
		return nil
	}

	ret := i.items[i.index]
	i.index++
	return ret
}

// ProofIterator is an iterator of byte slices (because gomobile doesn't support slice types except 1-D []byte).
type ProofIterator struct {
	items []*Proof
	index int
}

func newProofIterator(items []*Proof) *ProofIterator {
	return &ProofIterator{
		items: items,
		index: 0,
	}
}

func (i *ProofIterator) len() int {
	if i.items == nil {
		return 0
	}
	return len(i.items)
}

func (i *ProofIterator) HasNext() bool {
	return i.index < i.len()
}

func (i *ProofIterator) Next() *Proof {
	if !i.HasNext() {
		return nil
	}

	ret := i.items[i.index]
	i.index++
	return ret
}
