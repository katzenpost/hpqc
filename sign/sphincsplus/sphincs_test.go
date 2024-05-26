//go:build (darwin || linux) && amd64

// SPDX-FileCopyrightText: (c) 2022-2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package sphincsplus

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignatureScheme(t *testing.T) {
	t.Parallel()

	pubKey, privKey, err := Scheme().GenerateKey()
	require.NoError(t, err)
	message := []byte("i am a message")
	sig := Scheme().Sign(privKey, message, nil)
	require.True(t, Scheme().Verify(pubKey, message, sig, nil))
}

func TestSerialization(t *testing.T) {
	t.Parallel()

	pubKey, privKey, err := Scheme().GenerateKey()
	require.NoError(t, err)

	message := []byte("i am a message")
	sig := Scheme().Sign(privKey, message, nil)

	pubKeyBytes, err := pubKey.MarshalBinary()
	require.NoError(t, err)

	pubKey2, err := Scheme().UnmarshalBinaryPublicKey(pubKeyBytes)
	require.NoError(t, err)

	pubKey2Bytes, err := pubKey2.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, pubKey2Bytes, pubKeyBytes)
	require.True(t, Scheme().Verify(pubKey, message, sig, nil))
}

func TestSizes(t *testing.T) {
	t.Parallel()

	pubKey, privKey, err := Scheme().GenerateKey()
	require.NoError(t, err)

	message := []byte("i am a message")
	sig := Scheme().Sign(privKey, message, nil)
	require.True(t, Scheme().Verify(pubKey, message, sig, nil))

	privKeyBlob, err := privKey.MarshalBinary()
	require.NoError(t, err)

	pubKeyBlob, err := pubKey.MarshalBinary()
	require.NoError(t, err)

	t.Logf("privKey len %d", len(privKeyBlob))
	t.Logf("pubKey len %d", len(pubKeyBlob))
	t.Logf("sig len %d", len(sig))

	require.Equal(t, len(privKeyBlob), Scheme().PrivateKeySize())
	require.Equal(t, len(pubKeyBlob), Scheme().PublicKeySize())
	require.Equal(t, len(sig), Scheme().SignatureSize())
}
