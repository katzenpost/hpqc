// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package mkem provides multiparty KEM construction.
package mkem

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"github.com/katzenpost/chacha20poly1305"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/nike"
	coreUtil "github.com/katzenpost/hpqc/util"
)

// DEKSize is the byte length of one DEK ciphertext under the AEAD used
// here (ChaCha20-Poly1305 over a 32-byte msg_key): 12-byte nonce +
// 32-byte ciphertext + 16-byte tag = 60. The constant is kept for
// documentation and for sanity checks at the wire boundary; the in-
// memory representation is a plain []byte.
const DEKSize = 60

// Scheme is an MKEM scheme.
type Scheme struct {
	nike nike.Scheme
}

func NewScheme(scheme nike.Scheme) *Scheme {
	return &Scheme{
		nike: scheme,
	}
}

func (s *Scheme) GenerateKeyPair() (nike.PublicKey, nike.PrivateKey, error) {
	pubkey, privkey, err := s.nike.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	return pubkey, privkey, nil
}

func (s *Scheme) createCipher(key []byte) cipher.AEAD {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	return aead
}

func (s *Scheme) encrypt(key []byte, plaintext []byte) []byte {
	aead := s.createCipher(key)
	nonce := make([]byte, aead.NonceSize())
	_, err := rand.Reader.Read(nonce)
	if err != nil {
		panic(err)
	}
	return aead.Seal(nonce, nonce, plaintext, nil)
}

func (s *Scheme) decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	aead := s.createCipher(key)
	nonce := ciphertext[:aead.NonceSize()]
	ciphertext = ciphertext[aead.NonceSize():]
	return aead.Open(nil, nonce, ciphertext, nil)
}

func (s *Scheme) EnvelopeReply(privkey nike.PrivateKey, pubkey nike.PublicKey, plaintext []byte) *Ciphertext {
	secret := hash.Sum256(s.nike.DeriveSecret(privkey, pubkey))
	defer coreUtil.ExplicitBzero(secret[:])
	ciphertext := s.encrypt(secret[:], plaintext)
	c := &Ciphertext{
		EphemeralPublicKey: pubkey,
		DEKCiphertexts:     nil,
		Envelope:           ciphertext,
	}
	return c
}

func (s *Scheme) DecryptEnvelope(privkey nike.PrivateKey, pubkey nike.PublicKey, envelope []byte) ([]byte, error) {
	secret := hash.Sum256(s.nike.DeriveSecret(privkey, pubkey))
	defer coreUtil.ExplicitBzero(secret[:])
	plaintext, err := s.decrypt(secret[:], envelope)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (s *Scheme) Encapsulate(keys []nike.PublicKey, payload []byte) (nike.PrivateKey, *Ciphertext) {
	ephPub, ephPriv, err := s.nike.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	secrets := make([][hash.HashSize]byte, len(keys))
	defer func() {
		for i := range secrets {
			coreUtil.ExplicitBzero(secrets[i][:])
		}
	}()
	for i := 0; i < len(keys); i++ {
		secrets[i] = hash.Sum256(s.nike.DeriveSecret(ephPriv, keys[i]))
	}

	msgKey := make([]byte, 32)
	defer coreUtil.ExplicitBzero(msgKey)
	_, err = rand.Reader.Read(msgKey)
	if err != nil {
		panic(err)
	}
	ciphertext := s.encrypt(msgKey, payload)

	outCiphertexts := make([][]byte, len(secrets))
	for i := 0; i < len(secrets); i++ {
		outCiphertexts[i] = s.encrypt(secrets[i][:], msgKey)
	}

	c := &Ciphertext{
		EphemeralPublicKey: ephPub,
		DEKCiphertexts:     outCiphertexts,
		Envelope:           ciphertext,
	}
	return ephPriv, c
}

func (s *Scheme) Decapsulate(privkey nike.PrivateKey, ciphertext *Ciphertext) ([]byte, error) {
	ephSecret := hash.Sum256(s.nike.DeriveSecret(privkey, ciphertext.EphemeralPublicKey))
	defer coreUtil.ExplicitBzero(ephSecret[:])
	for i := 0; i < len(ciphertext.DEKCiphertexts); i++ {
		msgKey, err := s.decrypt(ephSecret[:], ciphertext.DEKCiphertexts[i])
		if err != nil {
			continue
		}
		defer coreUtil.ExplicitBzero(msgKey)
		return s.decrypt(msgKey, ciphertext.Envelope)
	}
	return nil, errors.New("failed to trial decrypt")
}
