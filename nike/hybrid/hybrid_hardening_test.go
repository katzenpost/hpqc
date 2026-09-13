// SPDX-License-Identifier: AGPL-3.0-only

package hybrid

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/nike/x448"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/util"
)

// testScheme is a cgo-free hybrid used to exercise the concatenation logic
// without the CTIDH bindings.
func testScheme() *Scheme {
	return &Scheme{
		first:  x25519.Scheme(rand.Reader),
		second: x448.Scheme(rand.Reader),
	}
}

// A buffer shorter than the first component key made FromBytes panic with a
// slice-out-of-range error instead of returning a clean error, and the same
// bytes reach it from a peer via UnmarshalBinaryPublicKey.
func TestPublicKeyFromBytesShortBufferErrorsNotPanic(t *testing.T) {
	s := testScheme()
	pub := s.NewEmptyPublicKey()
	require.NotPanics(t, func() {
		err := pub.FromBytes(make([]byte, 4))
		require.Error(t, err)
	}, "FromBytes must not panic on a short buffer")
}

func TestPrivateKeyFromBytesShortBufferErrorsNotPanic(t *testing.T) {
	s := testScheme()
	priv := s.NewEmptyPrivateKey()
	require.NotPanics(t, func() {
		err := priv.FromBytes(make([]byte, 4))
		require.Error(t, err)
	}, "FromBytes must not panic on a short buffer")
}

// A low-order point in one component yields an all-zero half; the old
// concatenation hid it behind the other valid half, so a caller's all-zero
// check could not see it. Per RFC 7748 Section 6.1 a degenerate component must
// not be hidden, so a degenerate half must zero the whole secret.
func TestDeriveSecretPropagatesDegenerateHalf(t *testing.T) {
	s := testScheme()
	_, priv, err := s.GenerateKeyPair()
	require.NoError(t, err)

	// Peer public key: a low-order (all-zero) x25519 half, a valid x448 half.
	lowFirst := s.first.NewEmptyPublicKey()
	require.NoError(t, lowFirst.FromBytes(make([]byte, x25519.PublicKeySize)))
	validSecond, _, err := s.second.GenerateKeyPair()
	require.NoError(t, err)
	peer := &publicKey{scheme: s, first: lowFirst, second: validSecond}

	secret := s.DeriveSecret(priv, peer)
	require.True(t, util.CtIsZero(secret),
		"a degenerate component half must zero the whole secret")
}

// The same must hold when the second component is the degenerate half.
func TestDeriveSecretPropagatesDegenerateSecondHalf(t *testing.T) {
	s := testScheme()
	_, priv, err := s.GenerateKeyPair()
	require.NoError(t, err)

	// Peer public key: a valid x25519 half, a low-order (all-zero) x448 half.
	validFirst, _, err := s.first.GenerateKeyPair()
	require.NoError(t, err)
	lowSecond := s.second.NewEmptyPublicKey()
	require.NoError(t, lowSecond.FromBytes(make([]byte, x448.PublicKeySize)))
	peer := &publicKey{scheme: s, first: validFirst, second: lowSecond}

	secret := s.DeriveSecret(priv, peer)
	require.True(t, util.CtIsZero(secret),
		"a degenerate second component half must zero the whole secret")
}
