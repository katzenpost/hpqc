// SPDX-License-Identifier: AGPL-3.0-only

package mkem

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
)

// A DEK ciphertext shorter than the AEAD nonce made decrypt slice out of
// range and panic; the bytes are attacker-controlled via a peer ciphertext.
// Decapsulate must reject it with an error instead.
func TestDecapsulateShortDEKErrorsNotPanic(t *testing.T) {
	s := NewScheme(x25519.Scheme(rand.Reader))
	ephPub, _, err := s.GenerateKeyPair()
	require.NoError(t, err)
	_, priv, err := s.GenerateKeyPair()
	require.NoError(t, err)

	ct := &Ciphertext{
		EphemeralPublicKey: ephPub,
		DEKCiphertexts:     [][]byte{make([]byte, 5)}, // shorter than the nonce
		Envelope:           make([]byte, DEKSize),
	}
	var out []byte
	var derr error
	require.NotPanics(t, func() {
		out, derr = s.Decapsulate(priv, ct)
	}, "Decapsulate must not panic on a short DEK ciphertext")
	require.Error(t, derr)
	require.Nil(t, out)
}

// A low-order ephemeral public key yields an all-zero shared secret. Per
// RFC 7748 Section 6.1 it must be detected and rejected, not hashed and used
// as a trial-decryption key.
func TestDecapsulateLowOrderEphemeralIsRejected(t *testing.T) {
	s := NewScheme(x25519.Scheme(rand.Reader))
	_, priv, err := s.GenerateKeyPair()
	require.NoError(t, err)

	lowPub, err := x25519.Scheme(rand.Reader).UnmarshalBinaryPublicKey(
		make([]byte, x25519.PublicKeySize))
	require.NoError(t, err)

	ct := &Ciphertext{
		EphemeralPublicKey: lowPub,
		DEKCiphertexts:     [][]byte{make([]byte, DEKSize)},
		Envelope:           make([]byte, DEKSize),
	}
	var out []byte
	var derr error
	require.NotPanics(t, func() {
		out, derr = s.Decapsulate(priv, ct)
	})
	require.ErrorIs(t, derr, ErrDegenerateSharedSecret)
	require.Nil(t, out)
}

// A low-order recipient public key (a malicious peer's PKI-published key)
// yields an all-zero shared secret. Per RFC 7748 Section 6.1 Encapsulate must
// refuse rather than encrypt the DEK under an attacker-predictable key.
func TestEncapsulateLowOrderRecipientErrors(t *testing.T) {
	s := NewScheme(x25519.Scheme(rand.Reader))
	lowPub, err := x25519.Scheme(rand.Reader).UnmarshalBinaryPublicKey(
		make([]byte, x25519.PublicKeySize))
	require.NoError(t, err)

	_, _, eerr := s.Encapsulate([]nike.PublicKey{lowPub}, []byte("payload"))
	require.ErrorIs(t, eerr, ErrDegenerateSharedSecret)

	_, _, eerr = s.EncapsulateWithEntropy(
		[]nike.PublicKey{lowPub}, []byte("payload"), rand.Reader)
	require.ErrorIs(t, eerr, ErrDegenerateSharedSecret)
}

// A low-order reply public key yields an all-zero shared secret; DecryptEnvelope
// must reject it (RFC 7748 Section 6.1) rather than hash and trial-decrypt.
func TestDecryptEnvelopeLowOrderIsRejected(t *testing.T) {
	s := NewScheme(x25519.Scheme(rand.Reader))
	_, priv, err := s.GenerateKeyPair()
	require.NoError(t, err)
	lowPub, err := x25519.Scheme(rand.Reader).UnmarshalBinaryPublicKey(
		make([]byte, x25519.PublicKeySize))
	require.NoError(t, err)

	_, derr := s.DecryptEnvelope(priv, lowPub, make([]byte, DEKSize))
	require.ErrorIs(t, derr, ErrDegenerateSharedSecret)
}

// A low-order reply recipient key yields an all-zero shared secret;
// EnvelopeReply must refuse rather than seal under it (RFC 7748 Section 6.1).
func TestEnvelopeReplyLowOrderRecipientErrors(t *testing.T) {
	s := NewScheme(x25519.Scheme(rand.Reader))
	_, priv, err := s.GenerateKeyPair()
	require.NoError(t, err)
	lowPub, err := x25519.Scheme(rand.Reader).UnmarshalBinaryPublicKey(
		make([]byte, x25519.PublicKeySize))
	require.NoError(t, err)

	_, eerr := s.EnvelopeReply(priv, lowPub, []byte("reply"))
	require.ErrorIs(t, eerr, ErrDegenerateSharedSecret)
}

// EncapsulateWithEntropy with valid keys still round-trips through Decapsulate,
// so the degenerate-key guard does not disturb the legitimate path.
func TestEncapsulateWithEntropyRoundTrip(t *testing.T) {
	s := NewScheme(x25519.Scheme(rand.Reader))
	pub, priv, err := s.GenerateKeyPair()
	require.NoError(t, err)

	payload := []byte("a legitimate mkem payload")
	_, ct, err := s.EncapsulateWithEntropy([]nike.PublicKey{pub}, payload, rand.Reader)
	require.NoError(t, err)

	out, err := s.Decapsulate(priv, ct)
	require.NoError(t, err)
	require.Equal(t, payload, out)
}
