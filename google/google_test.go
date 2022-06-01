package google

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

	gax "github.com/googleapis/gax-go/v2"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"

	// lots of poor naming in go-ethereum 👾
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func TestTxSign(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	const (
		testKeyName = "some/long/google/path/to/key"
		signAddrHex = "0xfcf56ab1d3170789d2ae15bed0542af26bc0b703"
		toAddrHex   = "0xdf0df53d518068c175c3d097213fbaed444b830d"
		testSigHex  = "3045022100f59239d9b5cb0afdd96f699dbf4b75cf3c0adba9bc2eb81187d5808ef8d22e2d02206ba7ac76faf5e95da0bd4414970a707990f72fd5e1c79d65c9c88d5acdfee51c"
		wantR       = "111075006843353154908519879268639247248126228380719928217241134964770822303277"
		wantS       = "48693728566302083515284341312053173995931100386764647948249870755750291105052"
	)
	toAddr := common.HexToAddress(toAddrHex)
	testTx := types.NewTx(&types.DynamicFeeTx{
		To:        &toAddr,
		Nonce:     99,
		GasFeeCap: big.NewInt(200e3),
		GasTipCap: big.NewInt(200e3),
		Gas:       2e6,
		Value:     big.NewInt(0),
		Data:      []byte{1, 2, 3},
	})
	testSigner := types.NewLondonSigner(big.NewInt(80001)) // Mumbai
	const wantDigestHex = "84194abff0612910554bdf0c287da7bb24318cbc0740f01bf84844c0ffabd8c7"

	mk := &ManagedKey{
		KeyName:      testKeyName,
		EthereumAddr: common.HexToAddress(signAddrHex),

		// mockup
		asymmetricSignFunc: func(ctx context.Context, req *kmspb.AsymmetricSignRequest, options ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			gotDigestHex := hex.EncodeToString(req.Digest.GetSha256())
			if gotDigestHex != wantDigestHex {
				t.Errorf("got assymetric sign request with digest 0x%s, want 0x%s", gotDigestHex, wantDigestHex)
			}

			sig, err := hex.DecodeString(testSigHex)
			if err != nil {
				return nil, fmt.Errorf("test has malformed signature: %w", err)
			}
			return &kmspb.AsymmetricSignResponse{Name: testKeyName, Signature: sig}, nil
		},
	}

	signedTx, err := mk.NewEthereumTransactor(ctx, testSigner).Signer(mk.EthereumAddr, testTx)
	if err != nil {
		t.Fatal("SignerFn from NewEthereumTransactor error:", err)
	}
	v, r, s := signedTx.RawSignatureValues()
	if i, _ := new(big.Int).SetString(wantR, 10); i.Cmp(r) != 0 {
		t.Errorf("got signature r %d, want %s", r, wantR)
	}
	if i, _ := new(big.Int).SetString(wantS, 10); i.Cmp(s) != 0 {
		t.Errorf("got signature s %d, want 1", s)
	}
	if big.NewInt(1).Cmp(v) != 0 {
		t.Errorf("got signature v %d, want 1", v)
	}
}
