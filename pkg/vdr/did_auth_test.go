package vdr

import (
	"fmt"
	didtypes "github.com/medibloc/panacea-core/v2/x/did/types"
	"github.com/medibloc/vc-sdk/pkg/vc"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/suite"
	"github.com/tendermint/tendermint/crypto/secp256k1"
	"testing"
)

type panaceaDIDAuthTestSuite struct {
	suite.Suite

	holderPrivKey   secp256k1.PrivKey
	attackerPrivKey secp256k1.PrivKey

	holderDID   string
	attackerDID string

	challenge string
	domain    string

	VDR *mockDIDClient
}

func TestPanaceaDIDAuthTestSuite(t *testing.T) {
	suite.Run(t, &panaceaDIDAuthTestSuite{})
}

func (suite *panaceaDIDAuthTestSuite) BeforeTest(_, _ string) {
	holderMnemonic, _ := newMnemonic()
	attackerMnemonic, _ := newMnemonic()

	suite.holderPrivKey, _ = generatePrivateKeyFromMnemonic(holderMnemonic)
	suite.attackerPrivKey, _ = generatePrivateKeyFromMnemonic(attackerMnemonic)

	suite.holderDID = didtypes.NewDID(suite.holderPrivKey.PubKey().Bytes())
	suite.attackerDID = didtypes.NewDID(suite.attackerPrivKey.PubKey().Bytes())

	holderPubKeyBase58 := base58.Encode(suite.holderPrivKey.PubKey().Bytes())
	attackerPubKeyBase58 := base58.Encode(suite.attackerPrivKey.PubKey().Bytes())

	holderDIDDoc := createDIDDoc(suite.holderDID, holderPubKeyBase58)
	attackerDIDDoc := createDIDDoc(suite.attackerDID, attackerPubKeyBase58)

	suite.VDR = newMockDIDClient(holderDIDDoc, attackerDIDDoc)

	suite.challenge = "this is a challenge"
	suite.domain = "https://my-domain.com"
}

func (suite *panaceaDIDAuthTestSuite) TestDIDAuthentication_Success() {
	panaceaVDR := NewPanaceaVDR(suite.VDR)
	f, err := vc.NewFramework(panaceaVDR)
	suite.NoError(err)

	proofOpts := &vc.ProofOptions{
		Controller:         suite.holderDID,
		VerificationMethod: fmt.Sprintf("%s#key1", suite.holderDID),
		SignatureType:      ecdsaSigType,
		Domain:             suite.domain,
		Challenge:          suite.challenge,
		Created:            "2017-06-18T21:19:10Z",
		ProofPurpose:       "authentication",
	}

	didAuth, err := f.AuthenticateDID(suite.holderPrivKey.Bytes(), proofOpts)
	suite.NoError(err)

	_, err = f.VerifyPresentation(didAuth)
	suite.NoError(err)
}

func (suite *panaceaDIDAuthTestSuite) TestDIDAuthentication_FailNotHolder() {
	panaceaVDR := NewPanaceaVDR(suite.VDR)
	f, err := vc.NewFramework(panaceaVDR)
	suite.NoError(err)

	proofOpts := &vc.ProofOptions{
		Controller:         suite.holderDID,
		VerificationMethod: fmt.Sprintf("%s#key1", suite.holderDID),
		SignatureType:      ecdsaSigType,
		Domain:             suite.domain,
		Challenge:          suite.challenge,
		Created:            "2017-06-18T21:19:10Z",
		ProofPurpose:       "authentication",
	}

	didAuth, err := f.AuthenticateDID(suite.attackerPrivKey.Bytes(), proofOpts)
	suite.NoError(err)

	_, err = f.VerifyPresentation(didAuth)
	suite.ErrorContains(err, "ecdsa: invalid signature")
}
