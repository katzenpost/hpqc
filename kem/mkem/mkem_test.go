// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package mkem provides multiparty KEM construction.
package mkem

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
)

func TestCiphertextMarshaling(t *testing.T) {
	ic := &IntermediaryCiphertext{
		EphemeralPublicKey: []byte("hello1"),
		DEKCiphertexts:     [][]byte{[]byte("yo123")},
		Envelope:           []byte("hello i am ciphertext"),
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
	nikeScheme := schemes.ByName("CTIDH1024-X25519")
	s := NewScheme(nikeScheme)

	replica1pub, replica1priv, err := s.GenerateKeyPair()
	require.NoError(t, err)

	replica2pub, replica2priv, err := s.GenerateKeyPair()
	require.NoError(t, err)

	secret := make([]byte, 32)
	_, err = rand.Reader.Read(secret)
	require.NoError(t, err)

	_, ciphertext := s.Encapsulate([]nike.PublicKey{replica1pub, replica2pub}, secret)

	secret1, err := s.Decapsulate(replica1priv, ciphertext)
	require.NoError(t, err)

	require.Equal(t, secret, secret1)

	secret2, err := s.Decapsulate(replica2priv, ciphertext)
	require.NoError(t, err)

	require.Equal(t, secret, secret2)
}

func TestMKEMProtocol(t *testing.T) {
	nikeScheme := schemes.ByName("CTIDH1024-X25519")
	s := NewScheme(nikeScheme)

	// replicas create their keys and publish them
	replica1pub, replica1priv, err := s.GenerateKeyPair()
	require.NoError(t, err)
	replica2pub, _, err := s.GenerateKeyPair()
	require.NoError(t, err)

	// client to replica
	request := make([]byte, 32)
	_, err = rand.Reader.Read(request)
	require.NoError(t, err)
	privKey1, envelope := s.Encapsulate([]nike.PublicKey{replica1pub, replica2pub}, request)

	// replica decrypts message from client
	request1, err := s.Decapsulate(replica1priv, envelope)
	require.NoError(t, err)
	require.Equal(t, request1, request)
	replyPayload := []byte("hello")
	reply1 := s.EnvelopeReply(replica1priv, envelope.EphemeralPublicKey, replyPayload)

	// client decrypts reply from replica
	plaintext, err := s.DecryptEnvelope(privKey1, replica1pub, reply1)
	require.NoError(t, err)

	require.Equal(t, replyPayload, plaintext)
}
