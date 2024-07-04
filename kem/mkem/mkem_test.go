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

	secret1, err := s.Decapsulate(replica1priv, ciphertext)
	require.NoError(t, err)

	require.Equal(t, secret, secret1)

	secret2, err := s.Decapsulate(replica2priv, ciphertext)
	require.NoError(t, err)

	require.Equal(t, secret, secret2)
}
