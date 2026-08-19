// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux && amd64 && useSqiSign

package sqisign

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/sign"
)

func TestSchemeSizes(t *testing.T) {
	t.Parallel()
	s := Scheme()
	require.Equal(t, "SQIsign-lvl1", s.Name())
	require.Equal(t, 65, s.PublicKeySize())
	require.Equal(t, 353, s.PrivateKeySize())
	require.Equal(t, 148, s.SignatureSize())
	require.False(t, s.SupportsContext())
}

func TestSignVerify(t *testing.T) {
	t.Parallel()
	s := Scheme()
	pub, priv, err := s.GenerateKey()
	require.NoError(t, err)

	msg := []byte("the quick brown fox jumps over the lazy dog")
	sig := s.Sign(priv, msg, nil)
	require.Equal(t, s.SignatureSize(), len(sig))
	require.True(t, s.Verify(pub, msg, sig, nil))

	// A tampered signature must not verify.
	bad := bytes.Clone(sig)
	bad[len(bad)/2] ^= 0x01
	require.False(t, s.Verify(pub, msg, bad, nil))

	// A tampered message must not verify under the original signature.
	badMsg := bytes.Clone(msg)
	badMsg[0] ^= 0x01
	require.False(t, s.Verify(pub, badMsg, sig, nil))
}

func TestMarshalRoundTrip(t *testing.T) {
	t.Parallel()
	s := Scheme()
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

	msg := []byte("round-trip")
	sig := s.Sign(priv2, msg, nil)
	require.True(t, s.Verify(pub2, msg, sig, nil))
}

func TestRandomisedSignaturesDiffer(t *testing.T) {
	t.Parallel()
	s := Scheme()
	_, priv, err := s.GenerateKey()
	require.NoError(t, err)

	msg := []byte("two signatures over the same message must differ under SQIsign's randomised signing")
	sigA := s.Sign(priv, msg, nil)
	sigB := s.Sign(priv, msg, nil)
	require.NotEqual(t, sigA, sigB)
}

func TestUnmarshalRejectsWrongSize(t *testing.T) {
	t.Parallel()
	s := Scheme()
	_, err := s.UnmarshalBinaryPublicKey(make([]byte, s.PublicKeySize()-1))
	require.ErrorIs(t, err, sign.ErrPubKeySize)
	_, err = s.UnmarshalBinaryPrivateKey(make([]byte, s.PrivateKeySize()+1))
	require.ErrorIs(t, err, sign.ErrPrivKeySize)
}

func TestContextOptionPanics(t *testing.T) {
	t.Parallel()
	s := Scheme()
	_, priv, err := s.GenerateKey()
	require.NoError(t, err)

	require.PanicsWithValue(t, sign.ErrContextNotSupported, func() {
		s.Sign(priv, []byte("hi"), &sign.SignatureOpts{Context: "ctx"})
	})
}

func TestDeriveKeyPanics(t *testing.T) {
	t.Parallel()
	s := Scheme()
	require.Panics(t, func() {
		s.DeriveKey(make([]byte, s.SeedSize()))
	})
}
