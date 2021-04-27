package vc

import (
	"crypto/sha256"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
)

type secp256k1Signer struct {
	privKey []byte
}

func newSecp256k1Signer(privKey []byte) *secp256k1Signer {
	return &secp256k1Signer{privKey: privKey}
}

func (s *secp256k1Signer) Sign(doc []byte) ([]byte, error) {
	priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), s.privKey)
	sig, err := priv.Sign(getSHA256(doc))
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	return serializeSig(sig), nil
}

// Serialize signature to R || S.
// R, S are padded to 32 bytes respectively.
// Reference: https://github.com/tendermint/tendermint/blob/be2ac87ab0e7133784e41eea6794636767ed8c32/crypto/secp256k1/secp256k1_nocgo.go#L58
func serializeSig(sig *btcec.Signature) []byte {
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()
	sigBytes := make([]byte, 64)
	// 0 pad the byte arrays from the left if they aren't big enough.
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)
	return sigBytes
}

func getSHA256(bytes []byte) []byte {
	hasher := sha256.New()
	hasher.Write(bytes)
	return hasher.Sum(nil)
}
