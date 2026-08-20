// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux && amd64 && !android

package hybrid

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/hpqc/sign/sqisign"
)

// TestSQIsignLvl1Ed25519Roundtrip exercises the hybrid end to end:
// keygen, sign, verify, and tamper-detection on both halves of the
// concatenated signature. The Falcon hybrid file in this package
// consumes JSON test vectors shared with the Python port; the SQIsign
// hybrid does not yet ship recorded vectors, so we rely on a fresh
// roundtrip here.
func TestSQIsignLvl1Ed25519Roundtrip(t *testing.T) {
	t.Parallel()
	s := SQIsignLvl1Ed25519
	require.Equal(t, "SQIsign-lvl1-Ed25519", s.Name())

	// Sizes must equal the sum of the two component schemes.
	require.Equal(t,
		sqisign.Scheme().PublicKeySize()+ed25519.Scheme().PublicKeySize(),
		s.PublicKeySize())
	require.Equal(t,
		sqisign.Scheme().PrivateKeySize()+ed25519.Scheme().PrivateKeySize(),
		s.PrivateKeySize())
	require.Equal(t,
		sqisign.Scheme().SignatureSize()+ed25519.Scheme().SignatureSize(),
		s.SignatureSize())

	pub, priv, err := s.GenerateKey()
	require.NoError(t, err)

	msg := []byte("hybrid hello: half SQIsign, half Ed25519")
	sig := s.Sign(priv, msg, nil)
	require.Equal(t, s.SignatureSize(), len(sig))
	require.True(t, s.Verify(pub, msg, sig, nil))

	// Flipping a byte in the SQIsign half (the first SignatureSize
	// bytes) must break verification.
	first := bytes.Clone(sig)
	first[0] ^= 0xff
	require.False(t, s.Verify(pub, msg, first, nil))

	// Flipping a byte in the Ed25519 half must break verification too.
	second := bytes.Clone(sig)
	second[len(second)-1] ^= 0xff
	require.False(t, s.Verify(pub, msg, second, nil))
}

func TestSQIsignLvl1Ed25519Marshal(t *testing.T) {
	t.Parallel()
	s := SQIsignLvl1Ed25519
	pub, priv, err := s.GenerateKey()
	require.NoError(t, err)

	pubBlob, err := pub.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, s.PublicKeySize(), len(pubBlob))

	privBlob, err := priv.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, s.PrivateKeySize(), len(privBlob))

	pub2, err := s.UnmarshalBinaryPublicKey(pubBlob)
	require.NoError(t, err)
	require.True(t, pub.Equal(pub2))

	priv2, err := s.UnmarshalBinaryPrivateKey(privBlob)
	require.NoError(t, err)
	require.True(t, priv.Equal(priv2))

	msg := []byte("marshal roundtrip then sign")
	sig := s.Sign(priv2, msg, nil)
	require.True(t, s.Verify(pub2, msg, sig, nil))
}
