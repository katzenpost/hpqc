// SPDX-License-Identifier: AGPL-3.0-only

package adapter

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
)

// A low-order peer point in the wire-KEM ciphertext must abort Decapsulate with
// an error (RFC 7748 Section 6.1), not panic and not use the all-zero secret.
func TestDecapsulateLowOrderPointErrorsNotPanic(t *testing.T) {
	s := FromNIKE(x25519.Scheme(rand.Reader))
	_, priv, err := s.GenerateKeyPair()
	require.NoError(t, err)

	ct := make([]byte, s.CiphertextSize()) // all-zero: a low-order point
	var out []byte
	var derr error
	require.NotPanics(t, func() {
		out, derr = s.Decapsulate(priv, ct)
	}, "Decapsulate must not panic on a low-order peer point")
	require.ErrorIs(t, derr, ErrLowOrderPoint)
	require.Nil(t, out)
}

// A low-order recipient key must abort Encapsulate the same way.
func TestEncapsulateLowOrderPointErrorsNotPanic(t *testing.T) {
	s := FromNIKE(x25519.Scheme(rand.Reader))

	pk, err := s.UnmarshalBinaryPublicKey(make([]byte, s.PublicKeySize()))
	require.NoError(t, err)

	var ct, ss []byte
	var eerr error
	require.NotPanics(t, func() {
		ct, ss, eerr = s.Encapsulate(pk)
	}, "Encapsulate must not panic on a low-order peer point")
	require.ErrorIs(t, eerr, ErrLowOrderPoint)
	require.Nil(t, ct)
	require.Nil(t, ss)
}
