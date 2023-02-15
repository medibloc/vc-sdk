package vc

import (
	"fmt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"net/http"
	"strings"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	jsonld "github.com/piprate/json-gold/ld"
)

type didResolver interface {
	Resolve(did string) (didDoc *did.Doc, err error)
}

type Framework struct {
	loader *ld.DocumentLoader
	vdr    didResolver
}

type FrameworkOption func(opts *Framework) error

func NewFramework(opts ...FrameworkOption) (*Framework, error) {
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

	framework := &Framework{
		loader: loader,
	}

	for _, opt := range opts {
		if err := opt(framework); err != nil {
			return nil, fmt.Errorf("framework option failed: %w", err)
		}
	}

	return framework, nil
}

// We can use verifiable.NewVDRKeyResolver instead of using FrameworkOption in the future version of aries

func WithVDR(vdr didResolver) FrameworkOption {
	return func(opts *Framework) error {
		opts.vdr = vdr
		return nil
	}
}

func (f *Framework) resolvePublicKey(did, keyID string) (*verifier.PublicKey, error) {
	didDoc, err := f.vdr.Resolve(did)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve did(%s): %w", did, err)
	}

	for _, verifications := range didDoc.VerificationMethods() {
		for _, verification := range verifications {
			if strings.Contains(verification.VerificationMethod.ID, keyID) {
				return &verifier.PublicKey{
					Type:  verification.VerificationMethod.Type,
					Value: verification.VerificationMethod.Value,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("public key with key ID %s is not found for  %s", keyID, did)
}
