// SPDX-License-Identifier: AGPL-3.0-only

//go:build !thinclient

package schemes

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/util"
)

var ctidhNames = []string{"ctidh511", "ctidh512", "ctidh1024", "ctidh2048"}

// Following the Curve25519 model, parsing accepts every key, including the
// base curve E0 (the all-zero key), without validation.
func TestCTIDHAcceptsBaseCurveE0PublicKey(t *testing.T) {
	for _, name := range ctidhNames {
		s := ByName(name)
		require.NotNil(t, s, name)
		zeros := make([]byte, s.PublicKeySize())
		pub, err := s.UnmarshalBinaryPublicKey(zeros)
		require.NoError(t, err, "%s: UnmarshalBinaryPublicKey must accept E0", name)
		require.True(t, util.CtIsZero(pub.Bytes()), name)
		require.NoError(t, s.NewEmptyPublicKey().FromBytes(zeros),
			"%s: FromBytes must accept E0", name)
	}
}

// The group action handles E0 so the degenerate case is caught at the
// boundary: DeriveSecret against E0 is the all-zero secret (not the caller's
// own key), Scheme.Blind of E0 returns nil, and PublicKey.Blind of E0 leaves
// it E0 rather than the blinder's own key.
func TestCTIDHCanonicalizesE0(t *testing.T) {
	for _, name := range ctidhNames {
		s := ByName(name)
		require.NotNil(t, s, name)
		e0 := s.NewEmptyPublicKey() // E0, not built via FromBytes
		priv := s.NewEmptyPrivateKey()
		require.True(t, util.CtIsZero(s.DeriveSecret(priv, e0)),
			"%s: DeriveSecret against E0 must be all-zero", name)
		require.Nil(t, s.Blind(e0, priv),
			"%s: Scheme.Blind of E0 must return nil", name)

		inPlace := s.NewEmptyPublicKey()
		require.NoError(t, inPlace.Blind(priv), name)
		require.True(t, util.CtIsZero(inPlace.Bytes()),
			"%s: PublicKey.Blind of E0 must stay E0", name)
	}
}

// A real generated key must still load and blind, so the E0 handling does not
// break legitimate use of any variant.
func TestCTIDHRealKeyOperations(t *testing.T) {
	for _, name := range ctidhNames {
		s := ByName(name)
		require.NotNil(t, s, name)

		pub, priv, err := s.GenerateKeyPair()
		require.NoError(t, err)

		blob, err := pub.MarshalBinary()
		require.NoError(t, err)
		loaded, err := s.UnmarshalBinaryPublicKey(blob)
		require.NoError(t, err)
		require.Equal(t, blob, loaded.Bytes(), name)

		require.False(t, util.CtIsZero(s.DeriveSecret(priv, pub)),
			"%s: a valid shared secret must not be all-zero", name)

		require.False(t, util.CtIsZero(s.Blind(pub, priv).Bytes()),
			"%s: blinding a valid key must not yield E0", name)
		require.NoError(t, loaded.Blind(priv), name)
	}
}

// The CTIDH-X25519 hybrid must propagate a nil Blind: a group member whose
// CTIDH half is the base curve E0 blinds to nil, not a key with a nil half.
func TestCTIDHX25519HybridBlindNil(t *testing.T) {
	s := ByName("CTIDH1024-X25519")
	require.NotNil(t, s)
	pub, priv, err := s.GenerateKeyPair()
	require.NoError(t, err)
	require.NotNil(t, s.Blind(pub, priv), "a valid hybrid key must blind to non-nil")

	blob, err := pub.MarshalBinary()
	require.NoError(t, err)
	// Zero the trailing CTIDH half (E0); the leading X25519 half stays valid.
	for i := x25519.PublicKeySize; i < len(blob); i++ {
		blob[i] = 0
	}
	degenerate, err := s.UnmarshalBinaryPublicKey(blob)
	require.NoError(t, err)
	require.Nil(t, s.Blind(degenerate, priv))
}
