package vc

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/piprate/json-gold/ld"
)

type Framework struct {
	loader   ld.DocumentLoader
	resolver *verifiable.DIDKeyResolver
}

func NewFramework(vdr vdr.Registry) (*Framework, error) {
	return &Framework{
		loader:   verifiable.CachingJSONLDLoader(),
		resolver: verifiable.NewDIDKeyResolver(vdr),
	}, nil
}
