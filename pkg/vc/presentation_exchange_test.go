package vc

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"
)

var (
	intFilterType = "integer"
	strFilterType = "string"

	required = presexch.Required

	bbsPrivKeyBz []byte
	bbsPubKeyBz  []byte

	vc              []byte
	pd              []byte
	pdWithPredicate []byte

	f      *Framework
	loader *ld.DocumentLoader
)

const (
	bbsKeyType         = "Bls12381G2Key2020"
	bbsSigType         = "BbsBlsSignature2020"
	verificationMethod = "did:panacea:76e12ec712ebc6f1c221ebfeb1f#key1"
)

func TestPresentationExchange_BBSProof(t *testing.T) {
	vp, err := f.CreatePresentationFromPD(vc, pd)
	require.NoError(t, err)

	vp.Context = append(vp.Context, "https://w3id.org/security/bbs/v1")

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	require.NoError(t, err)

	signedVP, err := f.SignPresentation(vpBytes, bbsPrivKeyBz, &ProofOptions{
		VerificationMethod: verificationMethod,
		SignatureType:      bbsSigType,
		Domain:             "https://my-domain.com",
		Challenge:          "challenge",
		Created:            "2023-01-01T10:10:10Z",
	})
	require.NoError(t, err)

	// if you want to print parsed VP, uncomment this block
	//
	//parsedVP, err := verifiable.ParsePresentation(signedVP, verifiable.WithPresPublicKeyFetcher(verifiable.SingleKey(bbsPubKeyBz, bbsKeyType)), verifiable.WithPresJSONLDDocumentLoader(loader))
	//res, err := json.MarshalIndent(parsedVP, "", "\t")
	//require.NoError(t, err)
	//fmt.Println(string(res))

	proofs, err := f.GetPresentationProofs(signedVP)
	require.NoError(t, err)
	require.True(t, proofs.HasNext())

	proof := proofs.Next()
	require.NotNil(t, proof)
	require.Equal(t, verificationMethod, proof.VerificationMethod)
	require.Equal(t, bbsSigType, proof.Type)
	require.Equal(t, "assertionMethod", proof.ProofPurpose)
	require.Equal(t, "https://my-domain.com", proof.Domain)
	require.Equal(t, "challenge", proof.Challenge)
	require.Equal(t, "2023-01-01T10:10:10Z", proof.Created)
	require.False(t, proofs.HasNext())
	require.Nil(t, proofs.Next())

	_, err = f.VerifyPresentation(signedVP, WithPresentationDefinition(pd))
	require.NoError(t, err)
}

func TestPresentationExchange_TamperedVP(t *testing.T) {
	vpFake, err := f.CreatePresentationFromPD(vc, pdWithPredicate)
	require.NoError(t, err)
	vpFake.Context = append(vpFake.Context, "https://w3id.org/security/bbs/v1")

	vp, err := f.CreatePresentationFromPD(vc, pd)
	require.NoError(t, err)

	vp.Context = append(vp.Context, "https://w3id.org/security/bbs/v1")

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	require.NoError(t, err)

	signedVP, err := f.SignPresentation(vpBytes, bbsPrivKeyBz, &ProofOptions{
		VerificationMethod: verificationMethod,
		SignatureType:      bbsSigType,
		Domain:             "https://my-domain.com",
		Challenge:          "challenge",
		Created:            "2023-01-01T10:10:10Z",
	})
	require.NoError(t, err)

	parsedVP, err := verifiable.ParsePresentation(signedVP, verifiable.WithPresPublicKeyFetcher(verifiable.SingleKey(bbsPubKeyBz, bbsKeyType)), verifiable.WithPresJSONLDDocumentLoader(loader))
	require.NoError(t, err)
	_, err = json.MarshalIndent(parsedVP, "", "\t")
	require.NoError(t, err)

	proofs, err := f.GetPresentationProofs(signedVP)
	require.NoError(t, err)
	require.True(t, proofs.HasNext())

	vpFake.Proofs = parsedVP.Proofs

	marshaledFakeVP, err := vpFake.MarshalJSON()
	require.NoError(t, err)
	_, err = f.VerifyPresentation(marshaledFakeVP)
	require.Error(t, err, "invalid BLS12-381 signature")
}

func TestPresentationExchange_InvalidPresentationDefinitionID(t *testing.T) {
	anotherPD := &presexch.PresentationDefinition{
		ID:      "this-is-another-presentation-definition",
		Purpose: "To test pd verification",
		InputDescriptors: []*presexch.InputDescriptor{{
			ID:      "example-pd",
			Purpose: "example pd",
			Schema: []*presexch.Schema{{
				URI:      "https://www.w3.org/2018/credentials#VerifiableCredential",
				Required: false,
			}},
			Constraints: &presexch.Constraints{
				Fields: []*presexch.Field{
					{
						Path: []string{"$.credentialSubject.degree"},
						Filter: &presexch.Filter{
							Type: &strFilterType,
						},
					},
				},
			},
		}},
	}
	anotherPDBz, err := json.Marshal(anotherPD)
	require.NoError(t, err)

	vp, err := f.CreatePresentationFromPD(vc, pd)
	require.NoError(t, err)

	vp.Context = append(vp.Context, "https://w3id.org/security/bbs/v1")

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	require.NoError(t, err)

	signedVP, err := f.SignPresentation(vpBytes, bbsPrivKeyBz, &ProofOptions{
		VerificationMethod: verificationMethod,
		SignatureType:      bbsSigType,
		Domain:             "https://my-domain.com",
		Challenge:          "challenge",
		Created:            "2023-01-01T10:10:10Z",
	})
	require.NoError(t, err)

	_, err = f.VerifyPresentation(signedVP, WithPresentationDefinition(anotherPDBz))
	require.Error(t, err, "is not matched with presentation definition")
}

func TestPresentationExchange_InvalidPresentationDefinitionSchema(t *testing.T) {
	anotherPD := &presexch.PresentationDefinition{
		ID: "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		InputDescriptors: []*presexch.InputDescriptor{{
			ID: "age_descriptor",
			Schema: []*presexch.Schema{{
				URI: fmt.Sprintf("https://my.test.context.jsonld/%s#%s", "d39768c7-0cfe-4619-8989-640130749be2", "CustomType"),
			}},
			Constraints: &presexch.Constraints{
				Fields: []*presexch.Field{
					{
						Path: []string{"$.credentialSubject.degree"},
						Filter: &presexch.Filter{
							Type: &strFilterType,
						},
					},
				},
			},
		}},
	}
	anotherPDBz, err := json.Marshal(anotherPD)
	require.NoError(t, err)

	vp, err := f.CreatePresentationFromPD(vc, pd)
	require.NoError(t, err)

	vp.Context = append(vp.Context, "https://w3id.org/security/bbs/v1")

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	require.NoError(t, err)

	signedVP, err := f.SignPresentation(vpBytes, bbsPrivKeyBz, &ProofOptions{
		VerificationMethod: verificationMethod,
		SignatureType:      bbsSigType,
		Domain:             "https://my-domain.com",
		Challenge:          "challenge",
		Created:            "2023-01-01T10:10:10Z",
	})
	require.NoError(t, err)

	_, err = f.VerifyPresentation(signedVP, WithPresentationDefinition(anotherPDBz))
	require.Error(t, err, "is not matched with presentation definition")
}

func init() {
	pubKey, privKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
	if err != nil {
		panic(err)
	}

	bbsPrivKeyBz, err = privKey.Marshal()
	if err != nil {
		panic(err)
	}

	bbsPubKeyBz, err = pubKey.Marshal()
	if err != nil {
		panic(err)
	}

	mockVDR := NewMockVDR(bbsPubKeyBz, bbsKeyType)
	f, _ = NewFramework(mockVDR)

	loader = f.loader

	cred := &verifiable.Credential{
		ID:      "https://my-verifiable-credential.com",
		Context: []string{verifiable.ContextURI, "https://w3id.org/security/bbs/v1"},
		Types:   []string{verifiable.VCType},
		Issuer: verifiable.Issuer{
			ID: "did:panacea:76e12ec712ebc6f1c221ebfeb1f",
		},
		Issued: &util.TimeWrapper{
			Time: time.Time{},
		},
		Subject: map[string]interface{}{
			"id":          "did:panacea:ebfeb1f712ebc6f1c276e12ec21",
			"first_name":  "Hansol",
			"last_name":   "Lee",
			"age":         21,
			"nationality": "Korea",
			"hobby":       "movie",
		},
	}
	vc, _ = cred.MarshalJSON()

	presDef := &presexch.PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		InputDescriptors: []*presexch.InputDescriptor{{
			ID:      "age_descriptor",
			Purpose: "Your age should be greater or equal to 18.",
			// required temporarily in v0.1.8 for schema verification.
			// schema will be optional by supporting presentation exchange v2
			// https://github.com/hyperledger/aries-framework-go/commit/66d9bf30de2f5cd6116adaac27f277b45077f26f
			Schema: []*presexch.Schema{{
				URI:      "https://www.w3.org/2018/credentials#VerifiableCredential",
				Required: false,
			}, {
				URI:      "https://w3id.org/security/bbs/v1",
				Required: false,
			}},
			Constraints: &presexch.Constraints{
				LimitDisclosure: &required,
				Fields: []*presexch.Field{
					{
						Path: []string{"$.credentialSubject.age"},
						Filter: &presexch.Filter{
							Type:    &intFilterType,
							Minimum: 18,
							Maximum: 30,
						},
					},
					{
						Path: []string{"$.credentialSubject.nationality"},
						Filter: &presexch.Filter{
							Type: &strFilterType,
							Enum: []presexch.StrOrInt{"Korea"},
						},
					},
				},
			},
		}},
	}
	pd, _ = json.Marshal(presDef)

	presDefPredicate := &presexch.PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055ff",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		InputDescriptors: []*presexch.InputDescriptor{{
			ID:      "age_descriptor2",
			Purpose: "Your age should be greater or equal to 18.",
			Schema: []*presexch.Schema{{
				URI:      "https://www.w3.org/2018/credentials#VerifiableCredential",
				Required: false,
			}, {
				URI:      "https://w3id.org/security/bbs/v1",
				Required: false,
			}},
			Constraints: &presexch.Constraints{
				LimitDisclosure: &required,
				Fields: []*presexch.Field{
					{
						Path:      []string{"$.credentialSubject.age"},
						Predicate: &required,
						Filter: &presexch.Filter{
							Type:    &intFilterType,
							Minimum: 18,
							Maximum: 30,
						},
					},
					{
						Path: []string{"$.credentialSubject.nationality"},
						Filter: &presexch.Filter{
							Type: &strFilterType,
							Enum: []presexch.StrOrInt{"Korea"},
						},
					},
				},
			},
		}},
	}
	pdWithPredicate, _ = json.Marshal(presDefPredicate)
}
