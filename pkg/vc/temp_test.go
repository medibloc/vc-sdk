package vc

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/go-bip39"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	didtypes "github.com/medibloc/panacea-core/v2/x/did/types"
	"github.com/medibloc/vc-sdk/pkg/vdr"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto/secp256k1"
	"testing"
	"time"
)

const (
	issuerDIDUnCompressed = "did:panacea:Dg6na5pzeZRiD9KDXhQHDfvuKPRpmaMPsV4PMSeJp1nn"
	holderDIDUnCompressed = "did:panacea:5VkRA8eHE9q33JWEKfBrzXi8z9mLW6QmJmKxWj8qmshV"

	issuerMnemonic = "camera basket torch quarter knock wool group program betray grow pigeon noise object stadium bulk foot since reunion bag trim forum expect hire humble"
	holderMnemonic = "large inquiry carbon expand wrist return prosper summer nasty nose chimney brain cotton obtain sell able book cave recipe asthma parent creek siren cancel"

	ecdsaSigType             = "EcdsaSecp256k1Signature2019"
	ecdsaVerificationType    = "EcdsaSecp256k1VerificationKey2019"
	issuerPubKeyUnCompressed = "RVZbWAgZ8ckzKC7fwwWFnyMASUSZ1ou1hNgqKqEJswMRCwXPAXdwrss7M8PMCtuiZ1CRfYW1wEFKRW58irHvnasr"
	holderPubKeyUnCompressed = "Rsr8o6j5fu4cx4ANiQ1nuxDwQaMzHFsvnm8FodGESAx6RGWqLysurY1SLaQ7fM3g2inAbiC7w2vW8P9xqnWWwf4t"

	issuerDID = "did:panacea:GU89om9nP7FUq4JHP8dMKnSaMe8VJ1YpQzf3TGN3fziM"
	holderDID = "did:panacea:4gcve5eXaZkqEbJ8K4NTHiaehCyGTTGFZUPBcF6hiTot"

	issuerPubKey = "28Diq1Q42qKCwMNFMXk8iVw5XhMrD48FxAbzxZdE1AvxY"
	holderPubKey = "29WjuQdBA2W3mQy7u31DrLzSWp1jY1huJKe9TYzKNnCyY"
)

func TestVPExchange(t *testing.T) {
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

	panaceaVDR := vdr.NewPanaceaVDR(testMockVDR{})
	framework, err := NewFramework(panaceaVDR)
	require.NoError(t, err)

	issuerPrivKey, err := GeneratePrivateKeyFromMnemonic(issuerMnemonic)
	require.NoError(t, err)

	signedVC, err := framework.SignCredential(vcBz, issuerPrivKey, &ProofOptions{
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

	holderPrivKey, err := GeneratePrivateKeyFromMnemonic(holderMnemonic)
	require.NoError(t, err)

	signedVP, err := framework.SignPresentation(vpBz, holderPrivKey, &ProofOptions{
		VerificationMethod: fmt.Sprintf("%s#key1", holderDID),
		SignatureType:      ecdsaSigType,
		Domain:             "https://my-domain.com",
		Challenge:          "this is a challenge",
		Created:            "2017-06-18T21:19:10Z",
	})
	require.NoError(t, err)

	_, err = framework.VerifyPresentation(signedVP, WithPresentationDefinition(pdBz))
	require.NoError(t, err)
}

type testMockVDR struct{}

func (m testMockVDR) GetDID(_ context.Context, did string) (*didtypes.DIDDocumentWithSeq, error) {
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
		return nil, fmt.Errorf("non existing did")
	}
}

func GeneratePrivateKeyFromMnemonic(mnemonic string) (secp256k1.PrivKey, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic")
	}

	hdPath := hd.NewFundraiserParams(0, 371, 0).String()
	master, ch := hd.ComputeMastersFromSeed(bip39.NewSeed(mnemonic, ""))

	return hd.DerivePrivateKeyForPath(master, ch, hdPath)
}
