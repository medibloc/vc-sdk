package vc

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/stretchr/testify/require"
)

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

	frameWork, err := NewFramework()
	require.NoError(t, err)

	privKey, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)

	fmt.Println(base64.RawURLEncoding.EncodeToString(privKey.Serialize()))
	fmt.Println(base64.RawURLEncoding.EncodeToString(privKey.PubKey().SerializeUncompressed()))

	vcBytes, err := frameWork.SignCredential([]byte(cred), privKey.Serialize(), &ProofOptions{
		VerificationMethod: "did:panacea:BFbUAkxqj3cXXYdNK9FAF9UuEmm7jCT5T77rXhBCvy2K#key1",
		SignatureType:      "EcdsaSecp256k1Signature2019",
	})
	require.NoError(t, err)
	fmt.Println(string(vcBytes))

	proofs, err := frameWork.GetCredentialProofs(vcBytes)
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

	err = frameWork.VerifyCredential(vcBytes, privKey.PubKey().SerializeUncompressed(), "EcdsaSecp256k1VerificationKey2019")
	require.NoError(t, err)

	pres := fmt.Sprintf(`{"@context": ["https://www.w3.org/2018/credentials/v1"],
		"id": "https://abc.com/vp/1",
		"type": ["VerifiablePresentation"],
		"verifiableCredential": [%s]
	}`, string(vcBytes))

	vpBytes, err := frameWork.SignPresentation([]byte(pres), privKey.Serialize(), &ProofOptions{
		VerificationMethod: "did:panacea:BFbUAkxqj3cXXYdNK9FAF9UuEmm7jCT5T77rXhBCvy2K#key1",
		SignatureType:      "EcdsaSecp256k1Signature2019",
		Domain:             "https://my-domain.com",
		Challenge:          "this is a challenge",
		Created:            "2017-06-18T21:19:10Z",
	})
	require.NoError(t, err)
	fmt.Println(string(vpBytes))

	proofs, err = frameWork.GetPresentationProofs(vpBytes)
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

	err = frameWork.VerifyPresentation(vpBytes, privKey.PubKey().SerializeUncompressed(), "EcdsaSecp256k1VerificationKey2019", nil)
	require.NoError(t, err)

	iterator, err := frameWork.GetCredentials(vpBytes)
	require.NoError(t, err)
	require.NotNil(t, iterator)

	require.True(t, iterator.HasNext())
	err = frameWork.VerifyCredential(iterator.Next(), privKey.PubKey().SerializeUncompressed(), "EcdsaSecp256k1VerificationKey2019")
	require.NoError(t, err)

	require.False(t, iterator.HasNext())
	require.Nil(t, iterator.Next())
}

// TODO: refactor tests (merging this test with the one above)
func TestFullScenarioWithBBS(t *testing.T) {
	bbsKeyType := "Bls12381G2Key2020"
	bbsSigType := "BbsBlsSignature2020"
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

	frameWork, err := NewFramework()
	require.NoError(t, err)

	pubKey, privKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)

	privKeyBz, err := privKey.Marshal()
	require.NoError(t, err)

	vcBytes, err := frameWork.SignCredential([]byte(cred), privKeyBz, &ProofOptions{
		VerificationMethod: "did:panacea:BFbUAkxqj3cXXYdNK9FAF9UuEmm7jCT5T77rXhBCvy2K#key1",
		SignatureType:      bbsSigType,
	})
	require.NoError(t, err)
	fmt.Println(string(vcBytes))

	proofs, err := frameWork.GetCredentialProofs(vcBytes)
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

	pubKeyBz, err := pubKey.Marshal()
	require.NoError(t, err)
	err = frameWork.VerifyCredential(vcBytes, pubKeyBz, bbsKeyType)
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
	vcBytes, err = frameWork.DeriveCredential(vcBytes, frame, nonce, pubKeyBz, bbsKeyType)
	require.NoError(t, err)

	pres := fmt.Sprintf(`{"@context": ["https://www.w3.org/2018/credentials/v1","https://w3id.org/security/bbs/v1"],
		"id": "https://abc.com/vp/1",
		"type": ["VerifiablePresentation"],
		"verifiableCredential": [%s]
	}`, string(vcBytes))

	vpBytes, err := frameWork.SignPresentation([]byte(pres), privKeyBz, &ProofOptions{
		VerificationMethod: "did:panacea:BFbUAkxqj3cXXYdNK9FAF9UuEmm7jCT5T77rXhBCvy2K#key1",
		SignatureType:      bbsSigType,
		Domain:             "https://my-domain.com",
		Challenge:          "this is a challenge",
		Created:            "2017-06-18T21:19:10Z",
	})
	require.NoError(t, err)
	fmt.Println(string(vpBytes))

	proofs, err = frameWork.GetPresentationProofs(vpBytes)
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

	err = frameWork.VerifyPresentation(vpBytes, pubKeyBz, bbsKeyType, nil)
	require.NoError(t, err)

	iterator, err := frameWork.GetCredentials(vpBytes)
	require.NoError(t, err)
	require.NotNil(t, iterator)

	require.True(t, iterator.HasNext())
	err = frameWork.VerifyCredential(iterator.Next(), pubKeyBz, bbsKeyType)
	require.NoError(t, err)

	require.False(t, iterator.HasNext())
	require.Nil(t, iterator.Next())
}