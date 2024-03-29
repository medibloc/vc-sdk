package vc

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	didtypes "github.com/medibloc/panacea-core/v2/x/did/types"

	"github.com/btcsuite/btcd/btcec"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/stretchr/testify/require"
)

func TestDIDAuthentication_Success(t *testing.T) {
	holderPrivKey, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)

	mockVDR := NewMockVDR(holderPrivKey.PubKey().SerializeUncompressed(), "EcdsaSecp256k1VerificationKey2019")
	f, err := NewFramework(mockVDR)
	require.NoError(t, err)

	holderDID := didtypes.NewDID(holderPrivKey.PubKey().SerializeCompressed())

	proofOpts := &ProofOptions{
		Controller:         holderDID,
		VerificationMethod: fmt.Sprintf("%s#key1", holderDID),
		SignatureType:      "EcdsaSecp256k1Signature2019",
		Domain:             "https://my-domain.com",
		Challenge:          "this is a challenge",
		Created:            "2017-06-18T21:19:10Z",
		ProofPurpose:       "authentication",
	}

	didAuth, err := f.AuthenticateDID(holderPrivKey.Serialize(), proofOpts)
	require.NoError(t, err)

	_, err = f.VerifyPresentation(didAuth)
	require.NoError(t, err)
}

func TestFullScenarioWithSecp256k1(t *testing.T) {
	cred := `{"@context": ["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],
	"issuer": "did:panacea:BFbUAkxqj3cXXYdNK9FAF9UuEmm7jCT5T77rXhBCvy2K",
	"id": "https://abc.com/1",
	"issuanceDate": "2010-01-01T19:13:24Z",
    "credentialSubject": {
      "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
		"degree": {
		  "type": "BachelorDegree",
		  "name": "Bachelor of Science and Arts"
		}
    },
    "type": [
      "VerifiableCredential",
      "UniversityDegreeCredential"
    ]}`

	privKey, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)

	fmt.Println(base64.RawURLEncoding.EncodeToString(privKey.Serialize()))
	fmt.Println(base64.RawURLEncoding.EncodeToString(privKey.PubKey().SerializeUncompressed()))

	mockVDR := NewMockVDR(privKey.PubKey().SerializeUncompressed(), "EcdsaSecp256k1VerificationKey2019")
	f, err := NewFramework(mockVDR)
	require.NoError(t, err)

	vcBytes, err := f.SignCredential([]byte(cred), privKey.Serialize(), &ProofOptions{
		VerificationMethod: "did:panacea:BFbUAkxqj3cXXYdNK9FAF9UuEmm7jCT5T77rXhBCvy2K#key1",
		SignatureType:      "EcdsaSecp256k1Signature2019",
	})
	require.NoError(t, err)
	fmt.Println(string(vcBytes))

	proofs, err := f.GetCredentialProofs(vcBytes)
	require.NoError(t, err)
	require.True(t, proofs.HasNext())
	proof := proofs.Next()
	require.NotNil(t, proof)
	require.Equal(t, "did:panacea:BFbUAkxqj3cXXYdNK9FAF9UuEmm7jCT5T77rXhBCvy2K#key1", proof.VerificationMethod)
	require.Equal(t, "EcdsaSecp256k1Signature2019", proof.Type)
	require.Equal(t, "assertionMethod", proof.ProofPurpose)
	require.Empty(t, proof.Domain)
	require.Empty(t, proof.Challenge)
	require.NotEmpty(t, proof.Created) // automatically set as current time by PanaceaFramework
	require.False(t, proofs.HasNext())
	require.Nil(t, proofs.Next())

	err = f.VerifyCredential(vcBytes)
	require.NoError(t, err)

	pres := fmt.Sprintf(`{"@context": ["https://www.w3.org/2018/credentials/v1"],
		"id": "https://abc.com/vp/1",
		"type": ["VerifiablePresentation"],
		"verifiableCredential": [%s]
	}`, string(vcBytes))

	vpBytes, err := f.SignPresentation([]byte(pres), privKey.Serialize(), &ProofOptions{
		VerificationMethod: "did:panacea:BFbUAkxqj3cXXYdNK9FAF9UuEmm7jCT5T77rXhBCvy2K#key1",
		SignatureType:      "EcdsaSecp256k1Signature2019",
		Domain:             "https://my-domain.com",
		Challenge:          "this is a challenge",
		Created:            "2017-06-18T21:19:10Z",
	})
	require.NoError(t, err)
	fmt.Println(string(vpBytes))

	proofs, err = f.GetPresentationProofs(vpBytes)
	require.NoError(t, err)
	require.True(t, proofs.HasNext())
	proof = proofs.Next()
	require.NotNil(t, proof)
	require.Equal(t, "did:panacea:BFbUAkxqj3cXXYdNK9FAF9UuEmm7jCT5T77rXhBCvy2K#key1", proof.VerificationMethod)
	require.Equal(t, "EcdsaSecp256k1Signature2019", proof.Type)
	require.Equal(t, "assertionMethod", proof.ProofPurpose)
	require.Equal(t, "https://my-domain.com", proof.Domain)
	require.Equal(t, "this is a challenge", proof.Challenge)
	require.Equal(t, "2017-06-18T21:19:10Z", proof.Created)
	require.False(t, proofs.HasNext())
	require.Nil(t, proofs.Next())

	_, err = f.VerifyPresentation(vpBytes)
	require.NoError(t, err)

	iterator, err := f.GetCredentials(vpBytes)
	require.NoError(t, err)
	require.NotNil(t, iterator)

	require.True(t, iterator.HasNext())
	err = f.VerifyCredential(iterator.Next())
	require.NoError(t, err)

	require.False(t, iterator.HasNext())
	require.Nil(t, iterator.Next())
}

// TODO: refactor tests (merging this test with the one above)
func TestFullScenarioWithBBS(t *testing.T) {
	cred := `{"@context": ["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1","https://w3id.org/security/bbs/v1"],
	"issuer": "did:panacea:BFbUAkxqj3cXXYdNK9FAF9UuEmm7jCT5T77rXhBCvy2K",
	"id": "https://abc.com/1",
	"issuanceDate": "2010-01-01T19:13:24Z",
    "credentialSubject": {
      "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
		"degree": {
		  "type": "BachelorDegree",
		  "name": "Bachelor of Science and Arts"
		}
    },
    "type": [
      "VerifiableCredential",
      "UniversityDegreeCredential"
    ]}`

	pubKey, privKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)

	pubKeyBz, err := pubKey.Marshal()
	require.NoError(t, err)

	privKeyBz, err := privKey.Marshal()
	require.NoError(t, err)

	mockVDR := NewMockVDR(pubKeyBz, bbsKeyType)
	f, err := NewFramework(mockVDR)
	require.NoError(t, err)

	vcBytes, err := f.SignCredential([]byte(cred), privKeyBz, &ProofOptions{
		VerificationMethod: "did:panacea:BFbUAkxqj3cXXYdNK9FAF9UuEmm7jCT5T77rXhBCvy2K#key1",
		SignatureType:      bbsSigType,
	})
	require.NoError(t, err)
	fmt.Println(string(vcBytes))

	proofs, err := f.GetCredentialProofs(vcBytes)
	require.NoError(t, err)
	require.True(t, proofs.HasNext())
	proof := proofs.Next()
	require.NotNil(t, proof)
	require.Equal(t, "did:panacea:BFbUAkxqj3cXXYdNK9FAF9UuEmm7jCT5T77rXhBCvy2K#key1", proof.VerificationMethod)
	require.Equal(t, bbsSigType, proof.Type)
	require.Equal(t, "assertionMethod", proof.ProofPurpose)
	require.Empty(t, proof.Domain)
	require.Empty(t, proof.Challenge)
	require.NotEmpty(t, proof.Created) // automatically set as current time by PanaceaFramework
	require.False(t, proofs.HasNext())
	require.Nil(t, proofs.Next())

	err = f.VerifyCredential(vcBytes)
	require.NoError(t, err)

	frame := []byte(`{"@context": ["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1","https://w3id.org/security/bbs/v1"],
  	"@explicit": true,
	"issuer": {},
	"id": {},
	"issuanceDate": {},
    "credentialSubject": {
      "@explicit": true,
      "id": {}
    },
    "type": [
      "VerifiableCredential",
      "UniversityDegreeCredential"
    ]}`)
	nonce := []byte("hola")
	vcBytes, err = f.DeriveCredential(vcBytes, frame, nonce, pubKeyBz, bbsKeyType)
	require.NoError(t, err)

	pres := fmt.Sprintf(`{"@context": ["https://www.w3.org/2018/credentials/v1","https://w3id.org/security/bbs/v1"],
		"id": "https://abc.com/vp/1",
		"type": ["VerifiablePresentation"],
		"verifiableCredential": [%s]
	}`, string(vcBytes))

	vpBytes, err := f.SignPresentation([]byte(pres), privKeyBz, &ProofOptions{
		VerificationMethod: "did:panacea:BFbUAkxqj3cXXYdNK9FAF9UuEmm7jCT5T77rXhBCvy2K#key1",
		SignatureType:      bbsSigType,
		Domain:             "https://my-domain.com",
		Challenge:          "this is a challenge",
		Created:            "2017-06-18T21:19:10Z",
	})
	require.NoError(t, err)
	fmt.Println(string(vpBytes))

	proofs, err = f.GetPresentationProofs(vpBytes)
	require.NoError(t, err)
	require.True(t, proofs.HasNext())
	proof = proofs.Next()
	require.NotNil(t, proof)
	require.Equal(t, "did:panacea:BFbUAkxqj3cXXYdNK9FAF9UuEmm7jCT5T77rXhBCvy2K#key1", proof.VerificationMethod)
	require.Equal(t, bbsSigType, proof.Type)
	require.Equal(t, "assertionMethod", proof.ProofPurpose)
	require.Equal(t, "https://my-domain.com", proof.Domain)
	require.Equal(t, "this is a challenge", proof.Challenge)
	require.Equal(t, "2017-06-18T21:19:10Z", proof.Created)
	require.False(t, proofs.HasNext())
	require.Nil(t, proofs.Next())

	_, err = f.VerifyPresentation(vpBytes)
	require.NoError(t, err)

	iterator, err := f.GetCredentials(vpBytes)
	require.NoError(t, err)
	require.NotNil(t, iterator)

	require.True(t, iterator.HasNext())
	err = f.VerifyCredential(iterator.Next())
	require.NoError(t, err)

	require.False(t, iterator.HasNext())
	require.Nil(t, iterator.Next())
}

type MockVDR struct {
	pubKeyBz   []byte
	pubKeyType string
}

func NewMockVDR(pubKeyBz []byte, pubKeyType string) *MockVDR {
	return &MockVDR{
		pubKeyBz:   pubKeyBz,
		pubKeyType: pubKeyType,
	}
}

func (v *MockVDR) Resolve(didID string, _ ...vdr.DIDMethodOption) (*did.DocResolution, error) {
	signingKey := did.VerificationMethod{
		ID:         didID + "#key1",
		Type:       v.pubKeyType,
		Controller: didID,
		Value:      v.pubKeyBz,
	}

	return &did.DocResolution{
		DIDDocument: &did.Doc{
			Context:            []string{"https://w3id.org/did/v1"},
			ID:                 didID,
			VerificationMethod: []did.VerificationMethod{signingKey},
		},
	}, nil
}

func (v *MockVDR) Create(_ string, _ *did.Doc, _ ...vdr.DIDMethodOption) (*did.DocResolution, error) {
	return nil, nil
}

func (v *MockVDR) Update(_ *did.Doc, _ ...vdr.DIDMethodOption) error {
	return nil
}

func (v *MockVDR) Deactivate(_ string, _ ...vdr.DIDMethodOption) error {
	return nil
}

func (v *MockVDR) Close() error {
	return nil
}
