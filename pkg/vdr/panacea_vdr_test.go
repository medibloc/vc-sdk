package vdr

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/go-bip39"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/medibloc/vc-sdk/pkg/vc"
	"github.com/tendermint/tendermint/crypto/secp256k1"
	"testing"
	"time"

	didtypes "github.com/medibloc/panacea-core/v2/x/did/types"
	"github.com/stretchr/testify/require"
)

const (
	issuerMnemonic = "camera basket torch quarter knock wool group program betray grow pigeon noise object stadium bulk foot since reunion bag trim forum expect hire humble"
	holderMnemonic = "large inquiry carbon expand wrist return prosper summer nasty nose chimney brain cotton obtain sell able book cave recipe asthma parent creek siren cancel"

	ecdsaSigType          = "EcdsaSecp256k1Signature2019"
	ecdsaVerificationType = "EcdsaSecp256k1VerificationKey2019"

	issuerDID = "did:panacea:GU89om9nP7FUq4JHP8dMKnSaMe8VJ1YpQzf3TGN3fziM"
	holderDID = "did:panacea:4gcve5eXaZkqEbJ8K4NTHiaehCyGTTGFZUPBcF6hiTot"

	issuerPubKey = "28Diq1Q42qKCwMNFMXk8iVw5XhMrD48FxAbzxZdE1AvxY"
	holderPubKey = "29WjuQdBA2W3mQy7u31DrLzSWp1jY1huJKe9TYzKNnCyY"
)

var (
	intFilterType = "integer"
	strFilterType = "string"
)

func TestPanaceaVDR_Resolve(t *testing.T) {
	panaceaVDR := NewPanaceaVDR(mockDIDClient{})

	did := "did:panacea:abcd1234"
	docRes, err := panaceaVDR.Resolve(did)
	require.NoError(t, err)
	require.Equal(t, did, docRes.DIDDocument.ID)
}

func TestPresentationExchange_WithPanaceaVDR(t *testing.T) {
	presDef := &presexch.PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		InputDescriptors: []*presexch.InputDescriptor{{
			ID:      "age_descriptor",
			Purpose: "Your age should be greater or equal to 18.",
			Schema: []*presexch.Schema{{
				URI:      "https://www.w3.org/2018/credentials#VerifiableCredential",
				Required: false,
			}, {
				URI:      "https://w3id.org/security/bbs/v1",
				Required: false,
			}},
			Constraints: &presexch.Constraints{
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
	pdBz, err := json.Marshal(presDef)
	require.NoError(t, err)

	cred := &verifiable.Credential{
		ID:      "https://my-verifiable-credential.com",
		Context: []string{verifiable.ContextURI},
		Types:   []string{verifiable.VCType},
		Issuer: verifiable.Issuer{
			ID: issuerDID,
		},
		Issued: &util.TimeWrapper{
			Time: time.Time{},
		},
		Subject: map[string]interface{}{
			"id":          holderDID,
			"first_name":  "Hansol",
			"last_name":   "Lee",
			"age":         21,
			"nationality": "Korea",
			"hobby":       "movie",
		},
	}

	vcBz, err := cred.MarshalJSON()
	require.NoError(t, err)

	panaceaVDR := NewPanaceaVDR(mockDIDClient{})
	framework, err := vc.NewFramework(panaceaVDR)
	require.NoError(t, err)

	issuerPrivKey, err := generatePrivateKeyFromMnemonic(issuerMnemonic)
	require.NoError(t, err)

	signedVC, err := framework.SignCredential(vcBz, issuerPrivKey, &vc.ProofOptions{
		VerificationMethod: fmt.Sprintf("%s#key1", issuerDID),
		SignatureType:      ecdsaSigType,
		Domain:             "https://my-domain.com",
		Challenge:          "this is a challenge",
		Created:            "2017-06-18T21:19:10Z",
	})
	require.NoError(t, err)

	vp, err := framework.CreatePresentationFromPD(signedVC, pdBz)
	require.NoError(t, err)

	vpBz, err := json.Marshal(vp)
	require.NoError(t, err)

	holderPrivKey, err := generatePrivateKeyFromMnemonic(holderMnemonic)
	require.NoError(t, err)

	signedVP, err := framework.SignPresentation(vpBz, holderPrivKey, &vc.ProofOptions{
		VerificationMethod: fmt.Sprintf("%s#key1", holderDID),
		SignatureType:      ecdsaSigType,
		Domain:             "https://my-domain.com",
		Challenge:          "this is a challenge",
		Created:            "2017-06-18T21:19:10Z",
	})
	require.NoError(t, err)

	_, err = framework.VerifyPresentation(signedVP, vc.WithPresentationDefinition(pdBz))
	require.NoError(t, err)
}

func generatePrivateKeyFromMnemonic(mnemonic string) (secp256k1.PrivKey, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic")
	}

	hdPath := hd.NewFundraiserParams(0, 371, 0).String()
	master, ch := hd.ComputeMastersFromSeed(bip39.NewSeed(mnemonic, ""))

	return hd.DerivePrivateKeyForPath(master, ch, hdPath)
}

var _ didClient = &mockDIDClient{}

type mockDIDClient struct{}

func (m mockDIDClient) GetDID(_ context.Context, did string) (*didtypes.DIDDocumentWithSeq, error) {
	switch did {
	case issuerDID:
		return &didtypes.DIDDocumentWithSeq{
			Document: &didtypes.DIDDocument{
				Id:       issuerDID,
				Contexts: &didtypes.JSONStringOrStrings{"https://www.w3.org/ns/did/v1"},
				VerificationMethods: []*didtypes.VerificationMethod{
					{
						Controller:      issuerDID,
						Id:              fmt.Sprintf("%s#key1", issuerDID),
						PublicKeyBase58: issuerPubKey,
						Type:            ecdsaVerificationType,
					},
				},
			},
			Sequence: 0,
		}, nil
	case holderDID:
		return &didtypes.DIDDocumentWithSeq{
			Document: &didtypes.DIDDocument{
				Id:       holderDID,
				Contexts: &didtypes.JSONStringOrStrings{"https://www.w3.org/ns/did/v1"},
				VerificationMethods: []*didtypes.VerificationMethod{
					{
						Controller:      holderDID,
						Id:              fmt.Sprintf("%s#key1", holderDID),
						PublicKeyBase58: holderPubKey,
						Type:            ecdsaVerificationType,
					},
				},
			},
			Sequence: 0,
		}, nil
	default:
		didDoc := didtypes.NewDIDDocument(did)
		return &didtypes.DIDDocumentWithSeq{
			Document: &didDoc,
		}, nil
	}
}
