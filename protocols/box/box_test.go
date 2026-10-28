// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package box

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/hybrid"
	"github.com/katzenpost/hpqc/nike/x25519"
)

func testSchemes() []nike.Scheme {
	return []nike.Scheme{
		x25519.Scheme(rand.Reader),
		hybrid.X25519CTIDH1024,
		hybrid.CTIDH1024X448,
	}
}

func TestRoundTrip(t *testing.T) {
	for _, n := range testSchemes() {
		t.Run(n.Name(), func(t *testing.T) {
			s := NewScheme(n)
			pub, priv, err := n.GenerateKeyPair()
			require.NoError(t, err)

			for _, size := range []int{0, 1, 32, 1500} {
				plaintext := make([]byte, size)
				_, err = rand.Read(plaintext)
				require.NoError(t, err)

				ct, err := s.Seal(pub, plaintext)
				require.NoError(t, err)
				require.Equal(t, size+s.Overhead(), len(ct))

				got, err := s.Open(priv, ct)
				require.NoError(t, err)
				require.Equal(t, plaintext, got)
			}
		})
	}
}

func TestOverhead(t *testing.T) {
	s := NewScheme(hybrid.X25519CTIDH1024)
	require.Equal(t, 176, s.Overhead())
	require.Equal(t, "box-X25519-CTIDH1024", s.Name())
}

func TestFreshEphemeral(t *testing.T) {
	n := x25519.Scheme(rand.Reader)
	s := NewScheme(n)
	pub, _, err := n.GenerateKeyPair()
	require.NoError(t, err)

	a, err := s.Seal(pub, []byte("same"))
	require.NoError(t, err)
	b, err := s.Seal(pub, []byte("same"))
	require.NoError(t, err)
	require.NotEqual(t, a, b)
}

func TestWrongRecipient(t *testing.T) {
	for _, n := range testSchemes() {
		t.Run(n.Name(), func(t *testing.T) {
			s := NewScheme(n)
			pub, _, err := n.GenerateKeyPair()
			require.NoError(t, err)
			_, other, err := n.GenerateKeyPair()
			require.NoError(t, err)

			ct, err := s.Seal(pub, []byte("for someone else"))
			require.NoError(t, err)
			_, err = s.Open(other, ct)
			require.ErrorIs(t, err, ErrOpen)
		})
	}
}

func TestTamper(t *testing.T) {
	n := x25519.Scheme(rand.Reader)
	s := NewScheme(n)
	pub, priv, err := n.GenerateKeyPair()
	require.NoError(t, err)

	ct, err := s.Seal(pub, []byte("do not touch"))
	require.NoError(t, err)

	for i := range ct {
		for _, bit := range []byte{0x01, 0x80} {
			bad := append([]byte(nil), ct...)
			bad[i] ^= bit
			_, err := s.Open(priv, bad)
			require.ErrorIs(t, err, ErrOpen, "flip at byte %d", i)
		}
	}
}

func TestTamperHybrid(t *testing.T) {
	n := hybrid.X25519CTIDH1024
	s := NewScheme(n)
	pub, priv, err := n.GenerateKeyPair()
	require.NoError(t, err)

	ct, err := s.Seal(pub, []byte("do not touch"))
	require.NoError(t, err)

	pkSize := n.PublicKeySize()
	for _, i := range []int{0, 31, 32, pkSize - 1, pkSize, len(ct) - 1} {
		bad := append([]byte(nil), ct...)
		bad[i] ^= 0x01
		_, err := s.Open(priv, bad)
		require.ErrorIs(t, err, ErrOpen, "flip at byte %d", i)
	}
}

func TestTruncated(t *testing.T) {
	for _, n := range testSchemes() {
		t.Run(n.Name(), func(t *testing.T) {
			s := NewScheme(n)
			pub, priv, err := n.GenerateKeyPair()
			require.NoError(t, err)

			ct, err := s.Seal(pub, []byte("whole"))
			require.NoError(t, err)

			for _, l := range []int{0, 1, n.PublicKeySize(), s.Overhead() - 1, s.Overhead(), len(ct) - 1} {
				_, err := s.Open(priv, ct[:l])
				require.ErrorIs(t, err, ErrOpen, "length %d", l)
			}
		})
	}
}

func TestDegenerateEphemeral(t *testing.T) {
	n := x25519.Scheme(rand.Reader)
	s := NewScheme(n)
	pub, priv, err := n.GenerateKeyPair()
	require.NoError(t, err)

	ct, err := s.Seal(pub, []byte("payload"))
	require.NoError(t, err)

	// The all-zero X25519 point has low order: every DH with it is zero.
	for i := range n.PublicKeySize() {
		ct[i] = 0
	}
	_, err = s.Open(priv, ct)
	require.ErrorIs(t, err, ErrOpen)
}

func TestDegenerateEphemeralHybrid(t *testing.T) {
	n := hybrid.X25519CTIDH1024
	s := NewScheme(n)
	pub, priv, err := n.GenerateKeyPair()
	require.NoError(t, err)

	ct, err := s.Seal(pub, []byte("payload"))
	require.NoError(t, err)

	// Zero only the X25519 half: the hybrid combiner zeroes the whole
	// secret when either component is degenerate.
	for i := range 32 {
		ct[i] = 0
	}
	_, err = s.Open(priv, ct)
	require.ErrorIs(t, err, ErrOpen)
}

func TestDegenerateRecipient(t *testing.T) {
	n := x25519.Scheme(rand.Reader)
	s := NewScheme(n)
	zero, err := n.UnmarshalBinaryPublicKey(make([]byte, n.PublicKeySize()))
	require.NoError(t, err)

	_, err = s.Seal(zero, []byte("payload"))
	require.ErrorIs(t, err, ErrDegenerateSharedSecret)
}
