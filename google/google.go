// Package google utilises the Key Management Service (KMS) from the Google
// Cloud Platform (GCP).
package google

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
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
	// E.g., "projects/my-project/locations/us-east1/keyRings/my-key-ring/cryptoKeys/my-key/cryptoKeyVersions/123"
	KeyName string

	ecdsa.PublicKey

	// AsymmetricSign method from a Google kms.KeyManagementClient.
	asymmetricSignFunc func(context.Context, *kmspb.AsymmetricSignRequest, ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
}

// NewManagedKey executes a fail-fast initialization.
func NewManagedKey(ctx context.Context, client *kms.KeyManagementClient, keyName string) (*ManagedKey, error) {
	key, err := publicKeyLookup(ctx, client, keyName)
	if err != nil {
		return nil, err
	}

	return &ManagedKey{
		KeyName:            keyName,
		PublicKey:          key,
		asymmetricSignFunc: client.AsymmetricSign,
	}, nil
}

func publicKeyLookup(ctx context.Context, client *kms.KeyManagementClient, keyName string) (ecdsa.PublicKey, error) {
	resp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: keyName})
	if err != nil {
		return ecdsa.PublicKey{}, fmt.Errorf("Google KMS public key %q lookup: %w", keyName, err)
	}

	block, _ := pem.Decode([]byte(resp.Pem))
	if block == nil {
		return ecdsa.PublicKey{}, fmt.Errorf("Google KMS public key %q PEM empty: %.130q", keyName, resp.Pem)
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return ecdsa.PublicKey{}, fmt.Errorf("Google KMS public key %q PEM block %q malformed: %w", keyName, block.Type, err)
	}

	ecKey, ok := key.(ecdsa.PublicKey)
	if !ok {
		return ecdsa.PublicKey{}, fmt.Errorf("Google KMS public key %q type %T is not an ecdsa.PublicKey", keyName, key)
	}

	return ecKey, nil
}

// NewEthereumTransactor retuns a KMS-backed instance. Ctx applies to the entire
// lifespan of the transactor.
func (mk *ManagedKey) NewEthereumTransactor(ctx context.Context, txIdentification types.Signer) *bind.TransactOpts {
	return &bind.TransactOpts{
		Context: ctx,
		From:    crypto.PubkeyToAddress(mk.PublicKey),
		Signer:  mk.NewEthereumSigner(ctx, txIdentification),
	}
}

// NewEthereumSigner retuns a KMS-backed instance. Ctx applies to the entire
// lifespan of the signer.
func (mk *ManagedKey) NewEthereumSigner(ctx context.Context, txIdentification types.Signer) bind.SignerFn {
	keyAddr := crypto.PubkeyToAddress(mk.PublicKey)

	return func(addr common.Address, tx *types.Transaction) (*types.Transaction, error) {
		if addr != keyAddr {
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

		// sign the transaction
		return tx.WithSignature(txIdentification, resp.Signature)
	}
}
