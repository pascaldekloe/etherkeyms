// Package google utilises the Key Management Service (KMS) from the Google
// Cloud Platform (GCP).
package google

import (
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"

	kms "cloud.google.com/go/kms/apiv1"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	gax "github.com/googleapis/gax-go/v2"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"

	// lots of poor naming in go-ethereum 👾
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// ManagedKey uses the Key Management Service (KMS) for blockchain operation.
type ManagedKey struct {
	KeyName string         // identifier within cloud project
	Addr    common.Address // public key identifier on the blockchain

	// AsymmetricSign method from a Google kms.KeyManagementClient.
	asymmetricSignFunc func(context.Context, *kmspb.AsymmetricSignRequest, ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
}

// NewManagedKey executes a fail-fast initialization.
// Key names from the Google cloud are slash-separated paths.
func NewManagedKey(ctx context.Context, client *kms.KeyManagementClient, keyName string) (*ManagedKey, error) {
	addr, err := resolveAddr(ctx, client, keyName)
	if err != nil {
		return nil, err
	}

	return &ManagedKey{
		KeyName:            keyName,
		Addr:               addr,
		asymmetricSignFunc: client.AsymmetricSign,
	}, nil
}

func resolveAddr(ctx context.Context, client *kms.KeyManagementClient, keyName string) (common.Address, error) {
	resp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: keyName})
	if err != nil {
		return common.Address{}, fmt.Errorf("Google KMS public key %q lookup: %w", keyName, err)
	}

	block, _ := pem.Decode([]byte(resp.Pem))
	if block == nil {
		return common.Address{}, fmt.Errorf("Google KMS public key %q PEM empty: %.130q", keyName, resp.Pem)
	}

	var info struct {
		AlgID pkix.AlgorithmIdentifier
		Key   asn1.BitString
	}
	_, err = asn1.Unmarshal(block.Bytes, &info)
	if err != nil {
		return common.Address{}, fmt.Errorf("Google KMS public key %q PEM block %q: %v", keyName, block.Type, err)
	}

	wantAlg := asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	if gotAlg := info.AlgID.Algorithm; !gotAlg.Equal(wantAlg) {
		return common.Address{}, fmt.Errorf("Google KMS public key %q ASN.1 algorithm %s intead of %s", keyName, gotAlg, wantAlg)
	}

	return common.BytesToAddress(crypto.Keccak256(info.Key.Bytes[1:])[12:]), nil
}

// NewEthereumTransactor retuns a KMS-backed instance. Ctx applies to the entire
// lifespan of the transactor.
func (mk *ManagedKey) NewEthereumTransactor(ctx context.Context, txIdentification types.Signer) *bind.TransactOpts {
	return &bind.TransactOpts{
		Context: ctx,
		From:    mk.Addr,
		Signer:  mk.NewEthereumSigner(ctx, txIdentification),
	}
}

// NewEthereumSigner retuns a KMS-backed instance. Ctx applies to the entire
// lifespan of the signer.
func (mk *ManagedKey) NewEthereumSigner(ctx context.Context, txIdentification types.Signer) bind.SignerFn {
	return func(addr common.Address, tx *types.Transaction) (*types.Transaction, error) {
		if addr != mk.Addr {
			return nil, bind.ErrNotAuthorized
		}

		// hash the transaction (with Keccak-256 probably)
		digest := txIdentification.Hash(tx).Bytes()

		// resolve a signature
		req := kmspb.AsymmetricSignRequest{
			Name: mk.KeyName,
			// The digest is probably not a standard SHA256.
			// Unclear why the API/client cares anyway. 🤨
			Digest: &kmspb.Digest{
				Digest: &kmspb.Digest_Sha256{
					Sha256: digest,
				},
			},
		}
		resp, err := mk.asymmetricSignFunc(ctx, &req)
		if err != nil {
			return nil, fmt.Errorf("Google KMS asymmetric sign operation unsuccessful: %w", err)
		}

		var parsedSig struct{ R, S *big.Int }
		_, err = asn1.Unmarshal(resp.Signature, &parsedSig)
		if err != nil || parsedSig.R == nil || parsedSig.S == nil {
			return nil, fmt.Errorf("Google KMS asymmetric sign operation gave malformed signature: %w", err)
		}
		RBytes := parsedSig.R.Bytes()
		SBytes := parsedSig.S.Bytes()
		if len(RBytes) > 32 || len(SBytes) > 32 {
			return nil, fmt.Errorf("Google KMS asymmetric sign operation gave %d-byte R and %d-byte S; want 32 bytes at most", len(RBytes), len(SBytes))
		}

		// Need uncompressed with "recovery ID" at end:
		// https://ethereum.stackexchange.com/a/53182/39582
		for recoveryID := byte(0); recoveryID < 4; recoveryID++ {
			// https://github.com/ethereum/go-ethereum/blob/de23cf910b814867d5c5d1ad6164835d79069638/core/types/transaction_signing.go#L491
			var sig [65]byte
			copy(sig[32-len(RBytes):32], RBytes)
			copy(sig[64-len(SBytes):64], SBytes)
			// https://github.com/ethereum/go-ethereum/blob/de23cf910b814867d5c5d1ad6164835d79069638/core/types/transaction.go#L227
			sig[64] = byte((txIdentification.ChainID().Uint64()*2)+35) + recoveryID

			var btcsig [65]byte
			btcsig[0] = recoveryID + 27
			copy(btcsig[33-len(RBytes):33], RBytes)
			copy(btcsig[65-len(SBytes):65], SBytes)
			txHash := txIdentification.Hash(tx)
			pubKey, _, err := btcecdsa.RecoverCompact(btcsig[:], txHash[:])
			if err != nil {
				return nil, fmt.Errorf("Google KMS asymmetric sign operation gave signature %#x, which is irrecoverable: %w", resp.Signature, err)
			}

			var addr common.Address
			copy(addr[:], crypto.Keccak256(pubKey.SerializeUncompressed()[1:])[12:])
			if addr == mk.Addr {
				// sign the transaction
				return tx.WithSignature(txIdentification, sig[:])
			}
		}

		return nil, fmt.Errorf("Google KMS asymmetric sign operation gave signature %#x; no recoverable signatures found", resp.Signature)
	}
}
