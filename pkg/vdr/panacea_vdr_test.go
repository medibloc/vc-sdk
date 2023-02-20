package vdr

import (
	"context"
	"testing"

	didtypes "github.com/medibloc/panacea-core/v2/x/did/types"
	"github.com/stretchr/testify/require"
)

func TestPanaceaVDR_Resolve(t *testing.T) {
	panaceaVDR := NewPanaceaVDR(mockDIDClient{})

	did := "did:panacea:abcd1234"
	docRes, err := panaceaVDR.Resolve(did)
	require.NoError(t, err)
	require.Equal(t, did, docRes.DIDDocument.ID)
}

var _ didClient = &mockDIDClient{}

type mockDIDClient struct{}

func (m mockDIDClient) GetDID(_ context.Context, did string) (*didtypes.DIDDocumentWithSeq, error) {
	didDoc := didtypes.NewDIDDocument(did)
	return &didtypes.DIDDocumentWithSeq{
		Document: &didDoc,
	}, nil
}
