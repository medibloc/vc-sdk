package vdr

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/gogo/protobuf/jsonpb"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	didtypes "github.com/medibloc/panacea-core/v2/x/did/types"
)

var _ vdr.Registry = &PanaceaVDR{}

type didClient interface {
	GetDID(context.Context, string) (*didtypes.DIDDocumentWithSeq, error)
}

type PanaceaVDR struct {
	didCli didClient
}

func NewPanaceaVDR(didCli didClient) *PanaceaVDR {
	return &PanaceaVDR{
		didCli: didCli,
	}
}

func (r *PanaceaVDR) Resolve(didID string, _ ...vdr.DIDMethodOption) (*did.DocResolution, error) {
	didDocWithSeq, err := r.didCli.GetDID(context.Background(), didID)
	if err != nil {
		return nil, fmt.Errorf("failed to get DID document: %w", err)
	}

	docBuf := new(bytes.Buffer)
	if err := new(jsonpb.Marshaler).Marshal(docBuf, didDocWithSeq.Document); err != nil {
		return nil, fmt.Errorf("failed to marshal DID document: %w", err)
	}

	doc, err := did.ParseDocument(docBuf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to parse DID document: %w", err)
	}

	return &did.DocResolution{
		DIDDocument: doc,
	}, nil
}

func (r *PanaceaVDR) Create(_ string, _ *did.Doc, _ ...vdr.DIDMethodOption) (*did.DocResolution, error) {
	return nil, errors.New("not implemented")
}

func (r *PanaceaVDR) Update(_ *did.Doc, _ ...vdr.DIDMethodOption) error {
	return errors.New("not implemented")
}

func (r *PanaceaVDR) Deactivate(_ string, _ ...vdr.DIDMethodOption) error {
	return errors.New("not implemented")
}

func (r *PanaceaVDR) Close() error {
	return errors.New("not implemented")
}

type PanaceaVDRKeyResolver struct {
	vdrKeyResolver *verifiable.VDRKeyResolver
}

func NewPanaceaVDRKeyResolver(vdr *PanaceaVDR) *PanaceaVDRKeyResolver {
	return &PanaceaVDRKeyResolver{
		vdrKeyResolver: verifiable.NewVDRKeyResolver(vdr),
	}
}

func (r *PanaceaVDRKeyResolver) PublicKeyFetcher() verifiable.PublicKeyFetcher {
	return func(issuerID, keyID string) (*verifier.PublicKey, error) {
		pubKey, err := r.vdrKeyResolver.PublicKeyFetcher()(issuerID, keyID)
		if err != nil {
			return nil, err
		}

		if pubKey.Type == "Secp256k1VerificationKey2018" && pubKey.JWK == nil {
			curve := btcec.S256()
			x, y := elliptic.UnmarshalCompressed(curve, pubKey.Value)
			if x != nil { // pubKey is compressed. so, convert it to uncompressed.
				pubKey.Value = elliptic.Marshal(curve, x, y)
			} // pubKey is uncompressed or invalid. so, do nothing
		}
		return pubKey, nil
	}
}
