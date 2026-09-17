// SPDX-License-Identifier: AGPL-3.0-only

package hybrid

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/hpqc/sign/ed25519"
)

// hardenTestScheme is a cheap Ed25519+Ed25519 hybrid used only to drive the
// composite marshaling paths without generating a slow post-quantum key.
func hardenTestScheme() *Scheme {
	base := ed25519.Scheme()
	return New("ed25519-ed25519-harden-test", base, base).(*Scheme)
}

// A short public-key input must not panic the composite unmarshal.
func TestUnmarshalBinaryPublicKeyRejectsShortInput(t *testing.T) {
	s := hardenTestScheme()
	var err error
	require.NotPanics(t, func() {
		_, err = s.UnmarshalBinaryPublicKey([]byte{1, 2, 3})
	}, "short public key must error, not panic")
	require.ErrorIs(t, err, sign.ErrPubKeySize)
}

// A short private-key input must not panic the composite unmarshal.
func TestUnmarshalBinaryPrivateKeyRejectsShortInput(t *testing.T) {
	s := hardenTestScheme()
	var err error
	require.NotPanics(t, func() {
		_, err = s.UnmarshalBinaryPrivateKey([]byte{1, 2, 3})
	}, "short private key must error, not panic")
	require.ErrorIs(t, err, sign.ErrPrivKeySize)
}

// PrivateKey.UnmarshalBinary must also reject a short input without panic.
func TestPrivateKeyUnmarshalBinaryRejectsShortInput(t *testing.T) {
	s := hardenTestScheme()
	_, priv, err := s.GenerateKey()
	require.NoError(t, err)
	hp := priv.(*PrivateKey)
	var uerr error
	require.NotPanics(t, func() {
		uerr = hp.UnmarshalBinary([]byte{1, 2, 3})
	}, "short input must error, not panic")
	require.ErrorIs(t, uerr, sign.ErrPrivKeySize)
}
