package vc

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/require"
)

func TestFullScenario(t *testing.T) {
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

	vcBytes, err := SignCredential([]byte(cred), privKey.Serialize(), &ProofOptions{
		VerificationMethod: "did:panacea:BFbUAkxqj3cXXYdNK9FAF9UuEmm7jCT5T77rXhBCvy2K#key1",
		SignatureType:      "EcdsaSecp256k1Signature2019",
	})
	require.NoError(t, err)

	fmt.Println(string(vcBytes))

	err = VerifyCredential(vcBytes, privKey.PubKey().SerializeUncompressed(), "EcdsaSecp256k1VerificationKey2019")
	require.NoError(t, err)

	pres := fmt.Sprintf(`{"@context": ["https://www.w3.org/2018/credentials/v1"],
		"id": "https://abc.com/vp/1",
		"type": ["VerifiablePresentation"],
		"verifiableCredential": [%s]
	}`, string(vcBytes))

	vpBytes, err := SignPresentation([]byte(pres), privKey.Serialize(), &ProofOptions{
		VerificationMethod: "did:panacea:BFbUAkxqj3cXXYdNK9FAF9UuEmm7jCT5T77rXhBCvy2K#key1",
		SignatureType:      "EcdsaSecp256k1Signature2019",
		Domain:             "https://my-domain.com",
		Challenge:          "this is a challenge",
	})
	require.NoError(t, err)

	fmt.Println(string(vpBytes))

	err = VerifyPresentation(vpBytes, privKey.PubKey().SerializeUncompressed(), "EcdsaSecp256k1VerificationKey2019")
	require.NoError(t, err)

	iterator, err := GetCredentials(vpBytes)
	require.NoError(t, err)
	require.NotNil(t, iterator)
	require.Equal(t, 1, iterator.Len())

	err = VerifyCredential(iterator.Next(), privKey.PubKey().SerializeUncompressed(), "EcdsaSecp256k1VerificationKey2019")
	require.NoError(t, err)

	require.Nil(t, iterator.Next())
}
