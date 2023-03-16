package vdr

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/go-bip39"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/medibloc/vc-sdk/pkg/vc"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/suite"
	"github.com/tendermint/tendermint/crypto/secp256k1"

	didtypes "github.com/medibloc/panacea-core/v2/x/did/types"
)

const (
	ecdsaSigType          = "EcdsaSecp256k1Signature2019"
	ecdsaVerificationType = "EcdsaSecp256k1VerificationKey2019"
)

var (
	intFilterType = "integer"
	strFilterType = "string"
)

type panaceaVDRTestSuite struct {
	suite.Suite

	issuerPrivKey secp256k1.PrivKey
	holderPrivKey secp256k1.PrivKey

	issuerDID string
	holderDID string

	VDR *mockDIDClient
}

func TestPanaceaVDRTestSuite(t *testing.T) {
	suite.Run(t, &panaceaVDRTestSuite{})
}

func (suite *panaceaVDRTestSuite) BeforeTest(_, _ string) {
	issuerMnemonic, _ := newMnemonic()
	holderMnemonic, _ := newMnemonic()

	suite.issuerPrivKey, _ = generatePrivateKeyFromMnemonic(issuerMnemonic)
	suite.holderPrivKey, _ = generatePrivateKeyFromMnemonic(holderMnemonic)

	suite.issuerDID = didtypes.NewDID(suite.issuerPrivKey.PubKey().Bytes())
	suite.holderDID = didtypes.NewDID(suite.holderPrivKey.PubKey().Bytes())

	issuerPubKeyBase58 := base58.Encode(suite.issuerPrivKey.PubKey().Bytes())
	holderPubKeyBase58 := base58.Encode(suite.holderPrivKey.PubKey().Bytes())

	issuerDIDDoc := createDIDDoc(suite.issuerDID, issuerPubKeyBase58)
	holderDIDDoc := createDIDDoc(suite.holderDID, holderPubKeyBase58)

	suite.VDR = newMockDIDClient(issuerDIDDoc, holderDIDDoc)
}

func (suite *panaceaVDRTestSuite) AfterTest(_, _ string) {
	suite.VDR.Close()
}

func (suite *panaceaVDRTestSuite) TestPresentationExchange_WithPanaceaVDR() {
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
	suite.NoError(err)

	cred := &verifiable.Credential{
		ID:      "https://my-verifiable-credential.com",
		Context: []string{verifiable.ContextURI},
		Types:   []string{verifiable.VCType},
		Issuer: verifiable.Issuer{
			ID: suite.issuerDID,
		},
		Issued: &util.TimeWrapper{
			Time: time.Time{},
		},
		Subject: map[string]interface{}{
			"id":          suite.holderDID,
			"first_name":  "Hansol",
			"last_name":   "Lee",
			"age":         21,
			"nationality": "Korea",
			"hobby":       "movie",
		},
	}

	vcBz, err := cred.MarshalJSON()
	suite.NoError(err)

	panaceaVDR := NewPanaceaVDR(suite.VDR)
	framework, err := vc.NewFramework(panaceaVDR)
	suite.NoError(err)

	signedVC, err := framework.SignCredential(vcBz, suite.issuerPrivKey, &vc.ProofOptions{
		VerificationMethod: fmt.Sprintf("%s#key1", suite.issuerDID),
		SignatureType:      ecdsaSigType,
		Domain:             "https://my-domain.com",
		Challenge:          "this is a challenge",
		Created:            "2017-06-18T21:19:10Z",
	})
	suite.NoError(err)

	vp, err := framework.CreatePresentationFromPD(signedVC, pdBz)
	suite.NoError(err)

	vpBz, err := json.Marshal(vp)
	suite.NoError(err)

	signedVP, err := framework.SignPresentation(vpBz, suite.holderPrivKey, &vc.ProofOptions{
		VerificationMethod: fmt.Sprintf("%s#key1", suite.holderDID),
		SignatureType:      ecdsaSigType,
		Domain:             "https://my-domain.com",
		Challenge:          "this is a challenge",
		Created:            "2017-06-18T21:19:10Z",
	})
	suite.NoError(err)

	_, err = framework.VerifyPresentation(signedVP, vc.WithPresentationDefinition(pdBz))
	suite.NoError(err)
}

var _ didClient = &mockDIDClient{}

type mockDIDClient struct {
	vdr map[string]*didtypes.DIDDocumentWithSeq
}

func newMockDIDClient(didDocs ...*didtypes.DIDDocumentWithSeq) *mockDIDClient {
	vdr := make(map[string]*didtypes.DIDDocumentWithSeq)
	mockDIDCli := &mockDIDClient{vdr}

	for _, doc := range didDocs {
		mockDIDCli.vdr[doc.Document.Id] = doc
	}

	return mockDIDCli
}

func (m *mockDIDClient) Close() error {
	return nil
}

func (m *mockDIDClient) GetDID(_ context.Context, did string) (*didtypes.DIDDocumentWithSeq, error) {
	return m.vdr[did], nil
}

func newMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

func generatePrivateKeyFromMnemonic(mnemonic string) (secp256k1.PrivKey, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic")
	}

	hdPath := hd.NewFundraiserParams(0, 371, 0).String()
	master, ch := hd.ComputeMastersFromSeed(bip39.NewSeed(mnemonic, ""))

	return hd.DerivePrivateKeyForPath(master, ch, hdPath)
}

func createDIDDoc(did, pubKeyBase58 string) *didtypes.DIDDocumentWithSeq {
	return &didtypes.DIDDocumentWithSeq{
		Document: &didtypes.DIDDocument{
			Id:              did,
			Contexts:        &didtypes.JSONStringOrStrings{"https://www.w3.org/ns/did/v1"},
			Authentications: []didtypes.VerificationRelationship{didtypes.NewVerificationRelationship(fmt.Sprintf("%s#key1", did))},
			VerificationMethods: []*didtypes.VerificationMethod{
				{
					Controller:      did,
					Id:              fmt.Sprintf("%s#key1", did),
					PublicKeyBase58: pubKeyBase58,
					Type:            ecdsaVerificationType,
				},
			},
		},
		Sequence: 0,
	}
}
