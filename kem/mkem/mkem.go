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
)

// Scheme is an MKEM scheme.
type Scheme struct {
	nike nike.Scheme
}

// FromNIKE creates a new KEM adapter Scheme
// using the given NIKE Scheme.
func FromNIKE(nike nike.Scheme) *Scheme {
	if nike == nil {
		panic("NIKE is nil")
	}
	return &Scheme{
		nike: nike,
	}
}

func (s *Scheme) GenerateKeyPair() (*PublicKey, *PrivateKey, error) {
	pubkey, privkey, err := s.nike.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	return &PublicKey{
			publicKey: pubkey,
		}, &PrivateKey{
			privateKey: privkey,
		}, nil
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

func (s *Scheme) Encapsulate(keys []*PublicKey, sharedSecret []byte) []byte {
	ephPub, ephPriv, err := s.nike.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	secrets := make([][hash.HashSize]byte, len(keys))
	for i := 0; i < len(keys); i++ {
		secrets[i] = hash.Sum256(s.nike.DeriveSecret(ephPriv, keys[i].publicKey))
	}

	msgKey := make([]byte, 32)
	_, err = rand.Reader.Read(msgKey)
	if err != nil {
		panic(err)
	}
	secretCiphertext := s.encrypt(msgKey, sharedSecret)

	outCiphertexts := make([][]byte, len(secrets))
	for i := 0; i < len(secrets); i++ {
		outCiphertexts[i] = s.encrypt(secrets[i][:], msgKey)
	}

	c := &Ciphertext{
		EphemeralPublicKey: &PublicKey{
			publicKey: ephPub,
		},
		DEKCiphertexts:   outCiphertexts,
		SecretCiphertext: secretCiphertext,
	}
	return c.Marshal()
}

func (s *Scheme) Decapsulate(privkey *PrivateKey, ciphertext []byte) ([]byte, error) {
	c, err := CiphertextFromBytes(s, ciphertext)
	if err != nil {
		return nil, err
	}

	ephSecret := hash.Sum256(s.nike.DeriveSecret(privkey.privateKey, c.EphemeralPublicKey.publicKey))
	for i := 0; i < len(c.DEKCiphertexts); i++ {
		msgKey, err := s.decrypt(ephSecret[:], c.DEKCiphertexts[i])
		if err != nil {
			continue
		}
		return s.decrypt(msgKey, c.SecretCiphertext)
	}
	return nil, errors.New("failed to trial decrypt")
}

// PrivateKey is an MKEM private key.
type PrivateKey struct {
	privateKey nike.PrivateKey
}

// PublicKey is an MKEM public key.
type PublicKey struct {
	publicKey nike.PublicKey
}
