package vc

import (
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	jsonld "github.com/piprate/json-gold/ld"
	"net/http"
)

type Framework struct {
	loader   *ld.DocumentLoader
	resolver *verifiable.VDRKeyResolver
}

type DidResolver interface {
	Resolve(did string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error)
}

func NewFramework(vdr DidResolver) (*Framework, error) {
	storeProvider := mem.NewProvider()
	contextStore, err := ldstore.NewContextStore(storeProvider)
	if err != nil {
		return nil, err
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(storeProvider)
	if err != nil {
		return nil, err
	}

	ctx, err := context.New(
		context.WithJSONLDContextStore(contextStore),
		context.WithJSONLDRemoteProviderStore(remoteProviderStore),
	)
	if err != nil {
		return nil, err
	}

	loader, err := ld.NewDocumentLoader(
		ctx,
		ld.WithRemoteDocumentLoader(jsonld.NewDefaultDocumentLoader(&http.Client{})),
	)
	if err != nil {
		return nil, err
	}

	resolver := verifiable.NewVDRKeyResolver(vdr)

	return &Framework{
		loader:   loader,
		resolver: resolver,
	}, nil
}
