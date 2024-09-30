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

	_, ciphertext := s.Encapsulate([]*PublicKey{replica1pub, replica2pub}, secret)

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

func TestMKEMProtocol(t *testing.T) {
	nikeName := "x25519"
	nike := schemes.ByName(nikeName)
	s := FromNIKE(nike)

	// replicas create their keys and publish them
	replica1pub, replica1priv, err := s.GenerateKeyPair()
	require.NoError(t, err)
	replica2pub, _, err := s.GenerateKeyPair()
	require.NoError(t, err)

	// client to replica
	request := make([]byte, 32)
	_, err = rand.Reader.Read(request)
	require.NoError(t, err)
	privKey1, envelopeRaw := s.Encapsulate([]*PublicKey{replica1pub, replica2pub}, request)
	envelope1, err := CiphertextFromBytes(s, envelopeRaw)
	require.NoError(t, err)

	// replica decrypts message from client
	request1, err := s.Decapsulate(replica1priv, envelopeRaw)
	require.NoError(t, err)
	require.Equal(t, request1, request)
	replyPayload := []byte("hello")
	reply1 := s.EnvelopeReply(replica1priv, envelope1.EphemeralPublicKey, replyPayload)

	// client decrypts reply from replica
	plaintext, err := s.DecryptEnvelope(privKey1, replica1pub, reply1)
	require.NoError(t, err)

	require.Equal(t, replyPayload, plaintext)
}
