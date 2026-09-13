// SPDX-License-Identifier: AGPL-3.0-only

package voucher

import (
	"errors"
	"testing"

	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike/x25519"
)

// A voucher public key whose X25519 half is a low-order point unmarshals but
// yields a degenerate shared secret; sealReply must surface the error rather
// than seal the reply under an attacker-predictable key.
func TestSealReplyDegenerateRecipientErrors(t *testing.T) {
	pub, _, err := sealNike.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := pub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	// Zero only the leading X25519 half (a low-order point); the CTIDH half
	// stays valid so UnmarshalBinaryPublicKey accepts the key and Encapsulate
	// reaches the degenerate shared secret.
	for i := 0; i < x25519.PublicKeySize; i++ {
		blob[i] = 0
	}

	if _, err := sealReply(blob, []byte("who"), make([]byte, VoucherSaltSize), nil); !errors.Is(err, mkem.ErrDegenerateSharedSecret) {
		t.Fatalf("want ErrDegenerateSharedSecret, got %v", err)
	}
}
