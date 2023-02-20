package vdr

import (
	"bytes"
	"context"
	"fmt"

	"github.com/gogo/protobuf/jsonpb"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
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
	return nil, nil
}

func (r *PanaceaVDR) Update(_ *did.Doc, _ ...vdr.DIDMethodOption) error {
	return nil
}

func (r *PanaceaVDR) Deactivate(_ string, _ ...vdr.DIDMethodOption) error {
	return nil
}

func (r *PanaceaVDR) Close() error {
	return nil
}
