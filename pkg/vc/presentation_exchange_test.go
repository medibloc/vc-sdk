package vc

import (
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"
)

var (
	intFilterType = "integer"
	strFilterType = "string"
)

func TestPresentationExchange(t *testing.T) {
	bbsKeyType := "Bls12381G2Key2020"
	bbsSigType := "BbsBlsSignature2020"
	verificationMethod := "did:panacea:76e12ec712ebc6f1c221ebfeb1f#key1"

	framework, err := NewFrameWork()
	require.NoError(t, err)
	loader := framework.loader

	pubKey, privKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)

	pubKeyBz, err := pubKey.Marshal()
	require.NoError(t, err)

	privKeyBz, err := privKey.Marshal()
	require.NoError(t, err)

	// verifiable credential
	vc := verifiable.Credential{
		ID:      "https://my-verifiable-credential.com",
		Context: []string{verifiable.ContextURI, "https://w3id.org/security/bbs/v1"},
		Types:   []string{verifiable.VCType},
		Issuer: verifiable.Issuer{
			ID: "did:panacea:76e12ec712ebc6f1c221ebfeb1f",
		},
		Issued: &util.TimeWrapper{
			Time: time.Time{},
		},
		Schemas: []verifiable.TypedID{{
			ID:   "hub://did:panacea:123/Collections/schema.us.gov/passport.json",
			Type: "JsonSchemaValidator2018",
		}},

		Subject: map[string]interface{}{
			"id":          "did:panacea:ebfeb1f712ebc6f1c276e12ec21",
			"first_name":  "Hansol",
			"last_name":   "Lee",
			"age":         21,
			"nationality": "Korea",
			"hobby":       "movie",
		},
	}

	//vcByte, err := vc.MarshalJSON()
	//require.NoError(t, err)
	//
	//signedVCByte, err := framework.SignCredential(vcByte, privKeyBz, &ProofOptions{
	//	VerificationMethod: verificationMethod,
	//	SignatureType:      bbsSigType,
	//})
	//require.NoError(t, err)
	//
	//signedVC, err := verifiable.ParseCredential(signedVCByte, )

	required := presexch.Required

	pd := &presexch.PresentationDefinition{
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
				//LimitDisclosure: &preferred,
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

	//loader, err := ldtestutil.DocumentLoader()
	//require.NoError(t, err)

	vp, err := pd.CreateVP([]*verifiable.Credential{&vc},
		loader,
		verifiable.WithJSONLDDocumentLoader(loader))
	//verifiable.WithPublicKeyFetcher(verifiable.SingleKey(pubKeyBz, bbsKeyType))
	require.NoError(t, err)

	vp.Context = append(vp.Context, "https://w3id.org/security/bbs/v1")

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	//fmt.Println(string(vpBytes))

	signedVP, err := framework.SignPresentation(vpBytes, privKeyBz, &ProofOptions{
		VerificationMethod: verificationMethod,
		SignatureType:      bbsSigType,
		Domain:             "https://my-domain.com",
		Challenge:          "challenge",
		Created:            "2023-01-01T10:10:10Z",
	})
	require.NoError(t, err)

	proofs, err := framework.GetPresentationProofs(signedVP)
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

	err = framework.VerifyPresentation(signedVP, pubKeyBz, bbsKeyType)
	require.NoError(t, err)

	//parsedVP, err := verifiable.ParsePresentation(signedVP, verifiable.WithPresPublicKeyFetcher(verifiable.SingleKey(pubKeyBz, bbsKeyType)))
	//require.NoError(t, err)
	//
	//res, err := json.MarshalIndent(parsedVP, "", "\t")
	//require.NoError(t, err)
	//fmt.Println(string(res))

	//fmt.Println(string(vpBytes))

	//pres, err := verifiable.ParsePresentation(vpBytes, verifiable.WithPublicKeyFetcher(verifiable.SingleKey(pubKeyBz, bbsKeyType)), verifiable.WithPresJSONLDDocumentLoader(loader))
	//require.NoError(t, err)
	//
	//vpvp, err := json.MarshalIndent(pres, "", "\t")
	//
	//fmt.Println(string(vpvp))
}
