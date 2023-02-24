package vc

import (
	"net/http"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	jsonld "github.com/piprate/json-gold/ld"
)

type Framework struct {
	loader         *ld.DocumentLoader
	vdrKeyResolver *verifiable.VDRKeyResolver
}

func NewFramework(vdrKeyResolver *verifiable.VDRKeyResolver) (*Framework, error) {
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

	return &Framework{
		loader:         loader,
		vdrKeyResolver: vdrKeyResolver,
	}, nil
}
