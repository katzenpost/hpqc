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
	dek := [DEKSize]byte{}
	_, err := rand.Reader.Read(dek[:])
	require.NoError(t, err)
	ic := &IntermediaryCiphertext{
		EphemeralPublicKey: []byte("hello1"),
		DEKCiphertexts:     []*[DEKSize]byte{&dek},
		Envelope:           []byte("hello i am ciphertext"),
	}
	blob1 := ic.Bytes()

	ic2 := &IntermediaryCiphertext{}
	err = ic2.FromBytes(blob1)
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
	replica0pub, replica0priv, err := s.GenerateKeyPair()
	require.NoError(t, err)
	replica1pub, replica1priv, err := s.GenerateKeyPair()
	require.NoError(t, err)

	// client to replica
	request := make([]byte, 31)
	_, err = rand.Reader.Read(request)
	require.NoError(t, err)
	privKey0, envelope := s.Encapsulate([]nike.PublicKey{replica0pub, replica1pub}, request)

	ct0 := &Ciphertext{
		EphemeralPublicKey: envelope.EphemeralPublicKey,
		DEKCiphertexts:     []*[DEKSize]byte{envelope.DEKCiphertexts[0]},
		Envelope:           envelope.Envelope,
	}

	ct1 := &Ciphertext{
		EphemeralPublicKey: envelope.EphemeralPublicKey,
		DEKCiphertexts:     []*[DEKSize]byte{envelope.DEKCiphertexts[1]},
		Envelope:           envelope.Envelope,
	}

	// replica0 decrypts message from client
	request0, err := s.Decapsulate(replica0priv, ct0)
	require.NoError(t, err)
	require.Equal(t, request0, request)
	// XXX require.Equal(t, len(ct0.DEKCiphertexts[0]), DEKSize)

	// replica1 decrypts message from client
	request1, err := s.Decapsulate(replica1priv, ct1)
	require.NoError(t, err)
	require.Equal(t, request1, request)

	request1, err = s.Decapsulate(replica1priv, ct0)
	require.Error(t, err)

	replyPayload := []byte("hello")
	reply0 := s.EnvelopeReply(replica0priv, envelope.EphemeralPublicKey, replyPayload)

	// client decrypts reply from replica
	plaintext, err := s.DecryptEnvelope(privKey0, replica0pub, reply0.Envelope)
	require.NoError(t, err)

	require.Equal(t, replyPayload, plaintext)
}
