package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/medibloc/vc-sdk/pkg/vc"
	"github.com/medibloc/vc-sdk/pkg/vdr"
)

func main() {
	didClient, err := vdr.NewDefaultPanaceaDIDClient("https://panacea-grpc-url:9090")
	if err != nil {
		log.Panic(err)
	}
	defer didClient.Close()

	framework, err := vc.NewFramework(vdr.NewPanaceaVDR(didClient))
	if err != nil {
		log.Panic(err)
	}

	var issuerDID string
	var issuerPrivKey []byte // a secp256k1 or bbs12381g2 private key

	var holderDID string
	var holderPrivKey []byte // a secp256k1 or bbs12381g2 private key

	// a credential without proof: https://www.w3.org/TR/vc-data-model/#credentials
	credential := []byte(fmt.Sprintf(
		`{
			"@context": ["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],
			"type": [
			  "VerifiableCredential",
			  "UniversityDegreeCredential"
			],
			"issuer": "%s",
			"id": "%s",
			"issuanceDate": "%s",
			"credentialSubject": {
			  "id": "%s",
			  "degree": {
				"type": "BachelorDegree",
				"name": "Bachelor of Science and Arts"
			  }
			}
		}`,
		issuerDID,
		uuid.New().String(),
		time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		holderDID,
	))

	// create a verifiable credential by signing credential
	verifiableCredential, err := framework.SignCredential(credential, issuerPrivKey, &vc.ProofOptions{
		VerificationMethod: fmt.Sprintf("%v#key1", issuerDID), // a verification method that you want to use
		SignatureType:      "EcdsaSecp256k1Signature2019",     // or BbsBlsSignature2020
	})

	// verify the verifiable credential (with proof verification)
	if err := framework.VerifyCredential(verifiableCredential); err != nil {
		log.Panic(err)
	}

	// prepare a presentation including the verifiable credential
	presentation := []byte(fmt.Sprintf(
		`{
			"@context": ["https://www.w3.org/2018/credentials/v1"],
			"id": "%s",
			"type": ["VerifiablePresentation"],
			"verifiableCredential": [%s]
		}`,
		uuid.New().String(), string(verifiableCredential),
	))

	// create a verifiable presentation by signing presentation
	verifiablePresentation, err := framework.SignPresentation(presentation, holderPrivKey, &vc.ProofOptions{
		VerificationMethod: fmt.Sprintf("%v#key1", holderDID), // a verification method that you want to use
		SignatureType:      "EcdsaSecp256k1Signature2019",     // or BbsBlsSignature2020,
		Domain:             "http://abc.com",                  // to prevent replay-attack
		Challenge:          "this is a challenge",             // to prevent replay-attack
		Created:            time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	})

	// verify the verifiable presentation (with proof verification)
	// TODO: use the presentation definition option
	if _, err := framework.VerifyPresentation(verifiablePresentation); err != nil {
		log.Panic(err)
	}

	// verify all verifiable credentials included in the presentation
	credIter, err := framework.GetCredentials(verifiablePresentation)
	if err != nil {
		log.Panic(err)
	}
	for credIter.HasNext() {
		if err := framework.VerifyCredential(credIter.Next()); err != nil {
			log.Panic(err)
		}
	}
}
