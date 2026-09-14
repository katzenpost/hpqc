// SPDX-License-Identifier: AGPL-3.0-only

package sntrup

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
)

// A correct-length but invalid ciphertext is reachable from unauthenticated
// peer wire-KEM bytes. Streamlined NTRU Prime confirms the ciphertext and used
// to panic on the confirmation failure; Decapsulate must instead return an
// error so a peer cannot crash the process.
func TestDecapsulateInvalidCiphertextErrorsNotPanic(t *testing.T) {
	s := Scheme()
	_, priv, err := s.GenerateKeyPair()
	require.NoError(t, err)

	ct := make([]byte, s.CiphertextSize()) // correct length, invalid content
	var out []byte
	var derr error
	require.NotPanics(t, func() {
		out, derr = s.Decapsulate(priv, ct)
	}, "Decapsulate must not panic on an invalid ciphertext")
	require.Error(t, derr)
	require.Nil(t, out)
}

// A wrong-length ciphertext must return an error, not panic.
func TestDecapsulateWrongCiphertextSizeErrorsNotPanic(t *testing.T) {
	s := Scheme()
	_, priv, err := s.GenerateKeyPair()
	require.NoError(t, err)

	var out []byte
	var derr error
	require.NotPanics(t, func() {
		out, derr = s.Decapsulate(priv, make([]byte, CiphertextSize-1))
	})
	require.ErrorIs(t, derr, kem.ErrCiphertextSize)
	require.Nil(t, out)
}

// DecapsulateTo used to panic on a wrong-length shared-key buffer; it must
// return an error instead.
func TestDecapsulateToWrongSharedKeySizeErrorsNotPanic(t *testing.T) {
	pk, sk, err := Scheme().GenerateKeyPair()
	require.NoError(t, err)
	ct, _, err := Scheme().Encapsulate(pk)
	require.NoError(t, err)

	var derr error
	require.NotPanics(t, func() {
		derr = sk.(*PrivateKey).DecapsulateTo(make([]byte, SharedKeySize-1), ct)
	})
	require.ErrorIs(t, derr, errSharedKeySize)
}
