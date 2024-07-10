// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package mkem provides multiparty KEM construction.
package mkem

import (
	"crypto/rand"
	"testing"

	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/stretchr/testify/require"
)

func TestCiphertextMarshaling(t *testing.T) {
	ic := &IntermediaryCiphertext{
		EphemeralPublicKey: []byte("hello1"),
		DEKCiphertexts:     [][]byte{[]byte("yo123")},
		SecretCiphertext:   []byte("hello i am ciphertext"),
	}
	blob1 := ic.Bytes()

	ic2 := &IntermediaryCiphertext{}
	err := ic2.FromBytes(blob1)
	require.NoError(t, err)
	blob2 := ic2.Bytes()
	require.Equal(t, blob1, blob2)

	ic3 := &IntermediaryCiphertext{}
	err = ic3.FromBytes(blob2)
	require.NoError(t, err)
	blob3 := ic3.Bytes()
	require.Equal(t, blob1, blob3)
}

func TestMKEMCorrectness(t *testing.T) {
	nikeName := "x25519"
	nike := schemes.ByName(nikeName)
	s := FromNIKE(nike)

	replica1pub, replica1priv, err := s.GenerateKeyPair()
	require.NoError(t, err)

	replica2pub, replica2priv, err := s.GenerateKeyPair()
	require.NoError(t, err)

	secret := make([]byte, 32)
	_, err = rand.Reader.Read(secret)
	require.NoError(t, err)

	ciphertext := s.Encapsulate([]*PublicKey{replica1pub, replica2pub}, secret)

	ciphertext2, err := CiphertextFromBytes(s, ciphertext)
	require.NoError(t, err)
	blob2 := ciphertext2.Marshal()
	require.Equal(t, ciphertext, blob2)

	secret1, err := s.Decapsulate(replica1priv, blob2)
	require.NoError(t, err)

	require.Equal(t, secret, secret1)

	secret2, err := s.Decapsulate(replica2priv, blob2)
	require.NoError(t, err)

	require.Equal(t, secret, secret2)
}
