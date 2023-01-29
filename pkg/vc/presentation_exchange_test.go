package vc

import (
	"encoding/json"
	"fmt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

var (
	intFilterType = "integer"
	strFilterType = "string"
)

func TestPresentationExchange(t *testing.T) {
	framework, err := NewFrameWork()
	require.NoError(t, err)
	loader := framework.loader

	// valid credential
	credValid := verifiable.Credential{
		ID:      "https://my-verifiable-credential.com",
		Context: []string{verifiable.ContextURI},
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

	required := presexch.Required
	//preferred := presexch.Preferred

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

	vp, err := pd.CreateVP([]*verifiable.Credential{&credValid}, loader, verifiable.WithJSONLDDocumentLoader(loader))
	require.NoError(t, err)

	vpBytes, err := json.MarshalIndent(vp, "", "\t")

	//fmt.Println(string(vpBytes))

	pres, err := verifiable.ParsePresentation(vpBytes, verifiable.WithPresDisabledProofCheck(), verifiable.WithPresJSONLDDocumentLoader(loader))
	require.NoError(t, err)

	vpvp, err := json.MarshalIndent(pres, "", "\t")

	fmt.Println(string(vpvp))
}
