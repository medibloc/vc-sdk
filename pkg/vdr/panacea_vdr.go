package vdr

import (
	"bytes"
	"context"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/gogo/protobuf/jsonpb"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	didtypes "github.com/medibloc/panacea-core/v2/x/did/types"
	"github.com/medibloc/vc-sdk/pkg/vc"
	"github.com/mr-tron/base58"
)

var _ vc.DidResolver = (*PanaceaVDR)(nil)

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

	var vms []*didtypes.VerificationMethod
	for _, vm := range didDocWithSeq.Document.VerificationMethods {
		pubKeyBz, err := base58.Decode(vm.PublicKeyBase58)
		if err != nil {
			return nil, fmt.Errorf("invalid base58 encoded public key: %w", err)
		}

		if btcec.IsCompressedPubKey(pubKeyBz) {
			pubKey, err := btcec.ParsePubKey(pubKeyBz, btcec.S256())
			if err != nil {
				return nil, fmt.Errorf("invalid secp256k1 public key of verification method: %w", err)
			}

			pubKeyStr := base58.Encode(pubKey.SerializeUncompressed())
			vm.PublicKeyBase58 = pubKeyStr
		}
		vms = append(vms, vm)
	}

	didDocWithSeq.Document.VerificationMethods = vms

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
