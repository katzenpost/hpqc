//go:build !windows
// +build !windows

// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package falcon

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/sign"
)

func allSchemes() []sign.Scheme {
	return []sign.Scheme{SchemePadded512(), SchemePadded1024()}
}

func TestSignVerify(t *testing.T) {
	t.Parallel()
	for _, s := range allSchemes() {
		s := s
		t.Run(s.Name(), func(t *testing.T) {
			pub, priv, err := s.GenerateKey()
			require.NoError(t, err)

			msg := []byte("the quick brown fox jumps over the lazy dog")
			sig := s.Sign(priv, msg, nil)
			require.Equal(t, s.SignatureSize(), len(sig))
			require.True(t, s.Verify(pub, msg, sig, nil))

			sig[0] ^= 0xff
			require.False(t, s.Verify(pub, msg, sig, nil))
		})
	}
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()
	for _, s := range allSchemes() {
		s := s
		t.Run(s.Name(), func(t *testing.T) {
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
		})
	}
}

func TestRandomisedSignaturesDiffer(t *testing.T) {
	t.Parallel()
	for _, s := range allSchemes() {
		s := s
		t.Run(s.Name(), func(t *testing.T) {
			_, priv, err := s.GenerateKey()
			require.NoError(t, err)

			msg := []byte("two signatures over the same message must differ under randomised Falcon")
			sigA := s.Sign(priv, msg, nil)
			sigB := s.Sign(priv, msg, nil)
			require.NotEqual(t, sigA, sigB)
		})
	}
}
