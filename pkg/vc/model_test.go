package vc

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCredentialAndPresentation(t *testing.T) {
	cred := &Credential{
		Context:   "https://www.w3.org/2018/credentials/examples/v1",
		ID:        "https://abc.com/vc/1",
		Type:      "UniversityDegreeCredential",
		Issuer:    "did:panacea:BFbUAkxqj3cXXYdNK9FAF9UuEmm7jCT5T77rXhBCvy2K",
		IssuedAt:  "2010-01-01T19:13:24Z",
		ExpiresAt: "2030-01-01T19:13:24Z",
		CredentialSubjectJSON: []byte(`{
			"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"degree": {
				"type": "BachelorDegree",
				"name": "Bachelor of Science and Arts"
			}
		}`),
	}

	credJSON, err := cred.MarshalJSON()
	require.NoError(t, err)
	expected := []byte(`{"@context":["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],"credentialSubject":{"degree":{"name":"Bachelor of Science and Arts","type":"BachelorDegree"},"id":"did:example:ebfeb1f712ebc6f1c276e12ec21"},"expirationDate":"2030-01-01T19:13:24Z","id":"https://abc.com/vc/1","issuanceDate":"2010-01-01T19:13:24Z","issuer":"did:panacea:BFbUAkxqj3cXXYdNK9FAF9UuEmm7jCT5T77rXhBCvy2K","type":["VerifiableCredential","UniversityDegreeCredential"]}`)
	require.Equal(t, expected, credJSON)
}

func TestPresentation(t *testing.T) {
	f, err := NewFramework(NewMockVDR(nil, ""))
	require.NoError(t, err)
	presentation := &Presentation{
		ID:     "https://abc.com/vp/1",
		Holder: "did:panacea:FAF9UuEmm7jCT5T77rXhBCvy2KBFbUAkxqj3cXXYdNK9",
	}
	err = presentation.AddVerifiableCredential([]byte(`{"@context":["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],"credentialSubject":{"degree":{"name":"Bachelor of Science and Arts","type":"BachelorDegree"},"id":"did:example:ebfeb1f712ebc6f1c276e12ec21"},"expirationDate":"2030-01-01T19:13:24Z","id":"https://abc.com/vc/1","issuanceDate":"2010-01-01T19:13:24Z","issuer":"did:panacea:BFbUAkxqj3cXXYdNK9FAF9UuEmm7jCT5T77rXhBCvy2K","type":["VerifiableCredential","UniversityDegreeCredential"]}`), f.loader)
	require.NoError(t, err)

	presentationJSON, err := presentation.MarshalJSON()
	require.NoError(t, err)
	expected := []byte(`{"@context":["https://www.w3.org/2018/credentials/v1"],"holder":"did:panacea:FAF9UuEmm7jCT5T77rXhBCvy2KBFbUAkxqj3cXXYdNK9","id":"https://abc.com/vp/1","type":"VerifiablePresentation","verifiableCredential":[{"@context":["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],"credentialSubject":{"degree":{"name":"Bachelor of Science and Arts","type":"BachelorDegree"},"id":"did:example:ebfeb1f712ebc6f1c276e12ec21"},"expirationDate":"2030-01-01T19:13:24Z","id":"https://abc.com/vc/1","issuanceDate":"2010-01-01T19:13:24Z","issuer":"did:panacea:BFbUAkxqj3cXXYdNK9FAF9UuEmm7jCT5T77rXhBCvy2K","type":["VerifiableCredential","UniversityDegreeCredential"]}]}`)
	require.Equal(t, expected, presentationJSON)
}
